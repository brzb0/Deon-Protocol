# Contributing to Deon Protocol

First off, thanks for taking the time to contribute!

The following is a set of guidelines for contributing to Deon Protocol. These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Deon Protocol. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

- **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/brzb0/Deon-Protocol/issues).
- If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Deon Protocol, including completely new features and minor improvements to existing functionality.

- Open a new issue with the label `enhancement`.
- Explain why this enhancement would be useful to most Deon Protocol users.

### Pull Requests

The process described here has several goals:

- Maintain Deon Protocol's quality.
- Fix problems that are important to users.
- Engage the technical community in working toward the best possible Deon Protocol.

Please follow these steps to have your contribution considered by the maintainers:

1.  **Fork the repo** and create your branch from `main`.
2.  If you've added code that should be tested, add tests.
3.  If you've changed APIs, update the documentation.
4.  Ensure the test suite passes.
5.  Make sure your code lints.
6.  Issue that pull request!

## Development Setup

1.  Ensure you have **Rust 1.75+** installed.
2.  Clone the repository:
    ```bash
    git clone https://github.com/brzb0/Deon-Protocol.git
    cd Deon-Protocol/deon_protocol
    ```
3.  Build the project:
    ```bash
    cargo build
    ```
4.  Run tests:
    ```bash
    cargo test
    ```

## Styleguides

### Rust

-   **rustfmt**: We use `cargo fmt` to keep code style consistent. Please run it before committing.
-   **clippy**: We use `cargo clippy` to catch common mistakes and improve code quality. Ensure your code is clippy-clean (no warnings).

### Commit Messages

-   Use the present tense ("Add feature" not "Added feature").
-   Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
-   Limit the first line to 72 characters or less.
-   Reference issues and pull requests liberally after the first line.
-   **Conventional Commits**: We encourage using the [Conventional Commits](https://www.conventionalcommits.org/) specification (e.g., `feat:`, `fix:`, `docs:`, `refactor:`).

## License

By contributing, you agree that your contributions will be licensed under its Apache License 2.0.
