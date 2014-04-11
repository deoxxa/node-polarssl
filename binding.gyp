{
  "targets": [
    {
      "target_name": "polarssl",
      "include_dirs": [
        "<!(node -e \"require('nan')\")",
      ],
      "sources": [
        "src/polarssl.cc",
      ],
      "dependencies": [
        "./deps/polarssl/binding.gyp:polarssl",
      ],
    },
  ],
}
