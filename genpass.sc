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
    
  }
  
  def create(): Unit = {
    if(!Files.exists(conf.root))
      Files.createDirectories(conf.root)
    if(Files.exists(conf.seed)) {
      println("WARNING! Changing the seed will change the generated passwords.")
      if(!yesOrNo(
        "Are you sure you want to overwrite the existing seed? (y/n): ")
      ) {
        return
      }
    }
    
    val lineReader: LineReaderBuilder.builder().build()
    
    Iterator
    .continually {
      lineReader.readLine("old password: ", 0)
    }
    .map {
      
    }
  }
  
  def change(): Unit = {
    
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
  
  def yesOrNo(prompt: String = "", default: Option[Boolean] = None): Boolean = {
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
  
  def getSeed(masterPw: Array[Char]): Array[Byte] = {
    // I try to mimic openssl because that is what genpass-bash uses. The
    // specific command line genpass-bash uses is
    // openssl aes256 -e -pass file:<(echo -n $newpassword) -pbkdf2
    // Here are some resources:
    // https://stackoverflow.com/questions/64295501/encryption-and-decryption-with-pbkdf2-and-aes256-practical-example-needed-ho
    // https://stackoverflow.com/questions/58823814/what-default-parameters-uses-openssl-pbkdf2
    // https://stackoverflow.com/questions/11783062/how-to-decrypt-file-in-java-encrypted-with-openssl-command-using-aes
    
    val encSeedIn = new FileInputStream(conf.seed.toFile())
    
    val pbkdfSalt = new Array[Byte](8)
    encSeedIn.skip(8) // skip the "Salted__" prefix
    encSeedIn.read(pbkdfSalt, 0, 8)
    
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val keySpec = new PBEKeySpec(masterPw, pbkdfSalt, 10000, 256)
    val key = new SecretKeySpec(
      factory.generateSecret(keySpec).getEncoded(), "AES")
    
    val iv = new Array[Byte](16) // todo: figure out how to get this
    
    val cipher = Cipher.getInstance("AES/CBC/PKCSC5Padding")
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv))
    val seedIn = new CipherInputStream(encSeedIn, cipher)
    seedIn.readAllBytes()
  }
  
  def applySalt(digest: MessageDigest): Unit = {
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
  }
  
  def initDigest(seed: Array[Byte]): MessageDigest = {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(seed)
    applySalt(digest)
    digest
  }
  
  def verifySeed(seed: Array[Byte]): Boolean = {
    val seedCheck = new FileInputStream(conf.seedCheck.toFile())
    val seedDigest = initDigest(seed).digest()
    MessageDigest.isEqual(
      seedCheck.readNBytes(seedDigest.length),
      seedDigest
    ) &&
    seedCheck.read() == -1
  }
}

@main
def main(args: String*) = GenPass.main(args.toArray)
