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
      ],
      "dependencies": [
        "./deps/polarssl/binding.gyp:polarssl",
      ],
    },
  ],
}
