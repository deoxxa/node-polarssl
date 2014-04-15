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
        "src/keygen.cc",
      ],
      "dependencies": [
        "./deps/polarssl/binding.gyp:polarssl",
      ],
    },
  ],
}
