{
  "targets": [
    {
      "target_name": "polarssl",
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
      ],
      "sources": [
        "src/polarssl.cc",
        "src/hash.cc",
        "src/hmac.cc",
        "src/keygen.cc",
        "src/key-rsa.cc",
        "src/random.cc",
      ],
      "dependencies": [
        "./deps/polarssl/binding.gyp:polarssl",
      ],
    },
  ],
}
