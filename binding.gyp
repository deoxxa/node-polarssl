{
  "targets": [
    {
      "target_name": "polarssl",
      "sources": [
        "src/polarssl.cc",
      ],
      "dependencies": [
        "./deps/polarssl/binding.gyp:polarssl",
      ],
    },
  ],
}
