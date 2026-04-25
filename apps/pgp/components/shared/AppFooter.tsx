/**
 * Sticky footer used on every top-level shell (onboarding, master
 * unlock, main tabbed view). The byline is here, with a top border as
 * a separator.
 */
export function AppFooter() {
  return (
    <footer className="border-border shrink-0 border-t px-4 py-3.5 text-center">
      <p className="text-muted-foreground text-xs">
        A privacy tool by{" "}
        <a
          href="https://amibeingpwned.com"
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline underline-offset-2 hover:opacity-80"
        >
          Am I Being Pwned
        </a>
      </p>
    </footer>
  );
}
