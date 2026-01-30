/**
 * @type {import('semantic-release').GlobalConfig}
 */
export default {
  branches: [
    "main",
    "+([0-9])?(.{+([0-9]),x}).x",
    { name: "beta", prerelease: true },
    { name: "alpha", prerelease: true },
    { name: "rc", prerelease: true },
  ],
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "angular",
        releaseRules: [
          { type: "perf", release: "minor" },
          { type: "chore", release: "patch" },
          { type: "style", release: "patch" },
          { type: "refactor", release: "patch" },
          { type: "docs", release: false },
          { type: "test", release: false },
        ],
        parserOpts: {
          noteKeywords: ["BREAKING CHANGE", "BREAKING CHANGES"],
        },
      },
    ],
    [
      "@semantic-release/release-notes-generator",
      {
        preset: "angular",
        parserOpts: {
          noteKeywords: ["BREAKING CHANGE", "BREAKING CHANGES", "BREAKING"],
        },
        writerOpts: {
          commitsSort: ["subject", "scope"],
        },
      },
    ],
    "@semantic-release/changelog",
    [
      "@semantic-release/git",
      {
        assets: ["CHANGELOG.md"],
      },
    ],
    "@semantic-release/github",
  ],
};
