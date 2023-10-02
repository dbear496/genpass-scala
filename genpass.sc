#!/usr/bin/env amm

object conf {
  var root = Paths.get(Properties.userHome, ".genpass")
  var seedFile = root.resolve("seed")
  var seedCheck = root.resolve("seed_check")
  var seedFileTmp = root.resolve("seed.tmp")
  var seedCheckTmp = root.resolve("seed_check.tmp")
  var tagsfile = root.resolve("tags")
  var charset = Charset.forName("UTF-8")
  var saltstr = "salt".getBytes(charset)
  var saltlen = 100000000
  var digestAlgo = "SHA-256"
  
  def setRoot(newRoot: Path = root): Unit = {
    root = newRoot
    seed = confRoot.resolve("seed")
    seedCheck = confRoot.resolve("seed_check")
    tags = confRoot.resolve("tags")
  }
}

object opts {
  // modes: normal / create / change / list / help
  var mode = "normal"
  
  // normal mode
  var copy = false
  var print = false
  var outputFile = None
  var outputDefault = true
  
  // create mode
  var plainSeedFile = null
  
  def parse(args: Array[String]): Unit = {
    val lifted = args.lift
    var positional = Seq.empty[String]
    var i = 0;
    while(args.sizeIs > i) {
      args(i) match {
        case "--create" => {
          mode = "create"
          plainSeedFile = lifted(i + 1)
            .orElse(throw new IllegalArgumentException(
              s"no filename supplied for option ${args(i)}"))
            .map(Paths.get)
            .get
        }
        case "--change" => mode = "change"
        case "--clipboard" | "-c" => { copy = true; outputDefault = false; }
        case "--no-clipboard" => copy = false
        case "--print" | "-p" => { print = true; outputDefault = false; }
        case "--no-print" => print = false
        case "--both" | "-b" =>
          { copy = true; print = true; outputDefault = false; }
        case "--output" | "-o" => {
          outputFile = lifted(i + 1)
          outputDefault = false
          if(outputFile.isEmpty)
            throw new IllegalArgumentException(
              s"no filename supplied for option ${args(i)}")
          i += 1
        }
        case "--list-tags" | "-l" => mode = "list"
        case "--home" => {
          val newHome = lifted(i + 1)
          if(newHome.isEmpty) {
            throw new IllegalArgumentException(
              s"no directory supplied for option ${args(i)}")
          }
          conf.setRoot()
          i += 1
        }
        case "--help" | "-h" => mode = "help"
        case opt if opt.startsWith("-") =>
          throw new IllegalArgumentException(s"unknown option ${opt}")
        case pos => positional :+= pos
      }
      i += 1
    }
    
    for(pos <- positional) {
      throw IllegalArgumentException(s"unexpected positional argument: ${pos}")
    }
    
    if(outputDefault)
      print = true
  }
}

object GenPass {
  lazy val random = new SecureRandom()
  lazy val pwLineReader = LineReaderBuilder.builder().build()
  
  def main(args: Array[String]): Unit = {
    opts.parse(args)
    opts.mode match {
      case "normal" => normal()
      case "create" => create()
      case "change" => change()
      case "list" => list()
      case "help" => help()
    }
  }
  
  def normal(): Unit = {
    // get the tag
    val tag = promptTag()
    val tagRaw = tag.getBytes(charset)
    
    // get the seed
    val seedDigest = Iterator
      .continually {
        pwLineReader.readLine("password: ", '\0')
      }
      .map(_.toCharArray)
      .map(getSeedStream)
      .map(seedDigest)
      .find(verifySeed((MessageDigest)_.clone()) ||
        {println("incorrect password, try again"); false})
      .get
    
    // generate the password
    val pwRaw = generatePassword(seedDigest, tagRaw)
    val pwStr = new String(pwRaw, charset)
    
    // output the password
    if(opts.copy) {
      val clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
      val cbOwner = new ClipboardOwner(){
        var ownsCb = true
        def lostOwnership(cb: Clipboard, contents: Transferable): Unit = {
          ownsCb = false
        }
      }
      val transferablePw = new StringSelection(pwStr)
      clipboard.setContents(transferablePw, cbOwner)
      
      // TODO: clear the clipboard after 30 seconds
      // NOTE: We want to clear the clipboard even after the terminal has been
      // returned. I cannot find a platform-independent way to do this.
      // NOTE: There is an inherent race condition where we may clear the wrong
      // data from the clipboard if the user copies something between the time
      // we check the contents and the time we perform the clear. I cannot find
      // any atomic way to do this.
      
      // Thread.sleep(30000)
      // if(
      //   Option(clipboard.getContents(null))
      //   .map(_.getTransferData(DataFlavor.stringFlavor))
      //   // TODO: catch UnsupportedFlavorException
      //   .exists(_ == pw)
      // ) {
      //   clipboard.setContents(null, null)
      // }
    }
    if(opts.print) {
      println(pwStr)
    }
    if(opts.outputFile.exists) {
      // TODO: try-with-resources
      val writer =
        new FileWriter(opts.outputFile.get.toFile, conf.charset, false)
      writer.write(pwStr)
      writer.close()
    }
  }
  
  def create(): Unit = {
    if(!Files.exists(conf.root))
      Files.createDirectories(conf.root)
    if(Files.exists(conf.seed)) {
      println("WARNING: Changing the seed will change generated passwords.")
      if(!promptYesOrNo(
        "Are you sure you want to overwrite the existing seed? (y/n): ")
      ) {
        return
      }
    }
    
    // get the new master password
    val masterPw = promptNewPassword()
    
    // setup seed digest
    val seedDigest = MessageDigest.getInstance(digestAlgo)
    
    // setup seed encryption
    val pbkdfSalt = new Array[Byte](8)
    random.nextBytes(pbkdfSalt)
    
    val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val keySpec = new PBEKeySpec(masterPw, pbkdfSalt, 10000,
      256 + cipher.getBlockSize() * 8)
    val keyAndIv = keyFactory.generateSecret(keyAndIvSpec).getEncoded()
    val key = new SecretKeySpec(keyAndIv, 0, 32, "AES")
    val iv = new IvParameterSpec(iv, 32, cipher.getBlockSize())
    
    val cipher = Cipher.getInstance("AES/CBC/PKCSC5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, key, iv)
    
    // encrypt the seed
    val encSeedOut = new FileOutputStream(conf.seedFileTmp.toFile, false)
    encSeedOut.write("Salted__".getBytes("US-ASCII"))
    encSeedOut.write(pbkdfSalt)
    new FileInputStream(plainSeedFile.toFile).transferTo(
      new DigestOutputStream(
        new CipherOutputStream(encSeedOut, cipher),
        seedDigest
      )
    )
    
    applySalt(seedDigest)
    val seedCheckOut = new FileOutputStream(conf.seedCheckTmp.toFile, false)
    seedCheckOut.write(seedDigest.digest())
    
    Files.copy(conf.seedFileTmp, conf.seedFile, ATOMIC_MOVE, REPLACE_EXISTING)
    Files.copy(conf.seedCheckTmp, conf.seedCheck, ATOMIC_MOVE, REPLACE_EXISTING)
    
    println("success")
  }
  
  def change(): Unit = {
    // get and verify the master password
    val oldPw = Iterator
      .continually {
        pwLineReader.readLine("old password: ", '\0')
      }
      .map(_.toCharArray)
      .find(verifySeed(seedDigest(getSeedStream(_))) ||
        {println("incorrect password, try again"); false})
      .get
    
    // get the new master password
    val newPw = promptNewPassword()
    
    
  }
  
  def list(): Unit = {
    if(!Files.isRegularFile(conf.tags)) {
      System.err.println(s"no tags file (${conf.tags})")
      return
    }
    
    Source.fromFile(conf.tags.toFile()).getLines()
    .foreach(println)
  }
  
  def help(): Unit = {
    print(
      "genpass [-c | --clipboard] [--no-clipboard] [-p | --print] " +
        "[-n | --no-print] [-b | --both] [{-o | --output} <file>] [--create] " +
        "[-h | --help]\n" +
      "  -c, --clipboard - copy the password to the clipboard and do not " +
        "print\n"
      "  --noclipbaord   - do not copy to the clipboard\n"
      "  -p, --print     - print the password to stdout and do not copy to " +
        "the clipboard (default)\n"
      "  -n, --no-print  - do not print to stdout\n"
      "  -b, --both      - print the password to stdout and copy it to the " +
        "clipboard\n"
      "  -o <file>\n"
      "  --output <file> - write the password to <file>\n"
      "  -l, --list-tags - print all known tags to standard out\n"
      "  --create        - create/change the master password. WARNING: This " +
        "will change the generated passwords!\n"
      "  -h, --help      - print this help message\n"
    )
  }
  
  def promptYesOrNo(prompt: String = "", default: Option[Boolean] = None): Boolean = {
    val lineReader: LineReaderBuilder.builder().build()
    Iterator
      .continually(lineReader.readLine(prompt))
      .flatMap{
        case "y" | "Y" => Some(true)
        case "n" | "N" => Some(false)
        case _ => default
      }
      .find(true).get
  }
  
  def promptTag(): String = {
    val lineReader: LineReaderBuilder.builder().build()
    Iterator
    .continually {
      lineReader.readLine("tag: ")
    }
    .filter(!_.isEmpty || {println("tag may not be blank"); false})
    .find { t =>
      Source.fromFile(conf.tagsfile.toFile()).getLines().exists(_ == t) ||
      promptYesOrNo(s"confirm new tag '${t}' (y/n): ") &&
      {
        // TODO: try-with-resources
        val tagsWriter = new FileWriter(conf.tagsfile, conf.charset, true)
        tagsWriter.write(t)
        tagsWriter.close()
        true
      }
    }.get
  }
  
  def promptNewPassword(): String = {
    Iterator
      .continually {
        pwLineReader.readLine("new password: ", '\0')
      }
      .find(_ == pwLineReader.readLine("confirm new password: ", '\0') ||
        {println("passwords do not match, try again"); false})
  }
  
  def createInitCipher(
    masterPw: Array[Char],
    pbkdfSalt: Array[Byte],
    opmode: Int
  ): Cipher = {
    val cipher = Cipher.getInstance("AES/CBC/PKCSC5Padding")
    val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val keySpec = new PBEKeySpec(masterPw, pbkdfSalt, 10000,
      256 + cipher.getBlockSize() * 8)
    val keyAndIv = keyFactory.generateSecret(keyAndIvSpec).getEncoded()
    val key = new SecretKeySpec(keyAndIv, 0, 32, "AES")
    val iv = new IvParameterSpec(iv, 32, cipher.getBlockSize())
    cipher.init(opmode, key, iv)
    cipher
  }
  
  def getSeedStream(masterPw: Array[Char]): InputStream = {
    // I try to mimic openssl because that is what genpass-bash uses. The
    // specific command line genpass-bash uses is
    // openssl aes256 -e -pass file:<(echo -n $newpassword) -pbkdf2
    // Here are some resources:
    // https://stackoverflow.com/questions/64295501/encryption-and-decryption-with-pbkdf2-and-aes256-practical-example-needed-ho
    // https://stackoverflow.com/questions/58823814/what-default-parameters-uses-openssl-pbkdf2
    // https://stackoverflow.com/questions/11783062/how-to-decrypt-file-in-java-encrypted-with-openssl-command-using-aes
    // https://github.com/openssl/openssl/blob/8ed76c62b5d3214e807e684c06efd69c6471c800/providers/implementations/kdfs/pbkdf2.c#L304
    
    val encSeedIn = new FileInputStream(conf.seed.toFile())
    
    val pbkdfSalt = new Array[Byte](8)
    encSeedIn.skip(8) // skip the "Salted__" prefix
    if(encSeedIn.read(pbkdfSalt, 0, 8) != 8)
      throw ...
    
    val cipher = createInitCipher(masterPw, pbkdfSalt, Cipher.DECRYPT_MODE)
    new CipherInputStream(encSeedIn, cipher)
  }
  
  def seedDigest(seedStream: InputStream): MessageDigest = {
    val digest = MessageDigest.getInstance(digestAlgo)
    new DigestInputStream(seedStream, digest)
      .transferTo(OutputStream.nullOutputStream)
    digest
  }
  
  def applySalt(digest: MessageDigest): MessageDigest = {
    if(conf.saltlen == 0)
      return
    
    require(conf.saltlen >= 0)
    require(conf.saltstr != null)
    require(conf.saltstr.length > 0)
    
    var len = conf.saltlen
    while(len >= conf.saltstr.length) {
      digest.update(saltstr)
      len -= conf.saltstr.length
    }
    digest.update(saltstr, 0, len)
    digest
  }
  
  def verifySeed(seedDigest: MessageDigest): Boolean = {
    applySalt(seedDigest)
    val digestBytes = seedDigest.digest()
    
    val seedCheck = new FileInputStream(conf.seedCheck.toFile())
    MessageDigest.isEqual(
      seedCheck.readNBytes(digestBytes.length),
      digestBytes
    ) &&
    seedCheck.read() == -1
  }
  
  def generatePassword(seedDigest: MessageDigest, tag: Array[Byte]): Array[Byte] = {
    seedDigest.update(tag)
    applySalt(seedDigest)
    Base64.getEncoder().encode(seedDigest.digest())
  }
}

@main
def main(args: String*) = GenPass.main(args.toArray)
