// Worded so it never reveals whether the address already has an account.
import { Icon, TextLink } from "./ui.tsx";

export function CheckEmail({ email, verification, joining }: { email?: string; verification: "email" | "operator"; joining?: boolean }) {
  return (
    <div className="space-y-3 text-sm" role="status">
      {verification === "email" ? (
        <>
          <p className="flex items-center gap-2 font-medium text-strong"><Icon name="mail-check" className="size-5 text-success" />Check your email</p>
          <p>
            If {email ? <strong className="break-all">{email}</strong> : "that address"} can be used here, a message with a confirmation link is on its way.
            {" "}The link works once, for 24 hours{joining ? ", and finishes joining the organization when you open it" : ""}.
          </p>
          <p className="text-muted">Nothing after a few minutes? Look in spam, then <TextLink to="/verify-email" className="underline">ask for a new link</TextLink>.</p>
        </>
      ) : (
        <>
          <p className="flex items-center gap-2 font-medium text-strong"><Icon name="user-cog" className="size-5 text-info" />Ask your administrator for the link</p>
          <p>
            This instance does not send email. If the address can be used here, the administrator can create its confirmation link on the server
            {" "}(<code>sentinel admin account email-link</code>) and give it to you{joining ? "; opening it also finishes joining the organization" : ""}.
          </p>
        </>
      )}
      <p>Once the address is confirmed, <TextLink to="/login" className="font-medium">sign in</TextLink> with it and your password. If this instance reviews new accounts, an administrator approves yours first.</p>
    </div>
  );
}
