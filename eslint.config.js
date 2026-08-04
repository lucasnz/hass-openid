export default [
  {
    files: ["custom_components/openid/*.js", "tests_js/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: {
        console: "readonly",
        document: "readonly",
        fetch: "readonly",
        MutationObserver: "readonly",
        process: "readonly",
        Request: "readonly",
        Response: "readonly",
        sessionStorage: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
        window: "readonly"
      }
    },
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-script-url": "error",
      "no-undef": "error",
      "no-unused-vars": ["error", { "argsIgnorePattern": "^_" }]
    }
  }
];
