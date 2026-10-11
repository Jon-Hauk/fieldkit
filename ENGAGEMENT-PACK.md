# Read-only posture snapshot — engagement page

**One page. Both of us sign it before anything runs.** It says what will be
looked at, what will not, what I take away, and what this is not.

## 1. Who is authorising this

| | |
|---|---|
| Name and title | |
| Business (legal entity) | |
| Microsoft 365 tenant (domain or tenant id) | |
| Machines in scope, if any | |
| Date | |

*"I am authorised to approve this read-only check on behalf of the business
named above."* — signature: ______________________

Having admin access to the tenant is not the same as being able to approve
this. If you are an IT contractor or MSP, the owner signs, or you attach the
owner's written go-ahead.

## 2. What will be looked at, and how

A **limited read-only snapshot** of the tenant's security posture on the date
above: users and their sign-in methods, privileged roles, guest accounts,
sign-in activity, Conditional Access and legacy-authentication settings,
external-sharing defaults, and dormant accounts. On a machine: the local
security baseline, installed protection, network configuration.

**Nothing is changed.** No settings, policies, users, roles or permissions are
created, modified or removed. The tool requests read-only permissions only;
the exact list is fixed by the tool version in the footer and published with
it.

**Sign-in is yours, not mine.** You sign in on your own machine while I watch.
If that is impractical, you create a read-only account for the listed checks
and disable it when we are done. I do not accept administrator credentials.

**Permissions you grant outlast the check.** The first sign-in may show a
Microsoft consent screen for the read permissions. Accept for that account
only; do not tick "Consent on behalf of your organization". The consent stays
in your tenant after we finish, so at the end I show you how to remove it. The
tool refuses to run if the sign-in carries any permission beyond its published
read-only list, so leftover consent from earlier work stops the check rather
than widening it.

## 3. What is collected, and what leaves with me

| Data class | In the report |
|---|---|
| Counts and settings (how many, on/off, which policy) | Yes |
| Account and device names | Only where needed to explain a finding, a privileged exposure, or a fix |
| Sign-in timestamps, guest lists, role holders | Pseudonymised by default; named only as above |
| Raw tool output | **Stays on your machine** if the check ran there |

If I hold raw output to write the report, it is stored locally and encrypted,
never in a consumer cloud-sync folder, never in a code repository, and it is
**deleted within 7 days** of delivering the report. Client notes I keep use
first names only and hold no raw artifacts.

## 4. What this is, and is not

This is a read-only snapshot of what the tool could see on one date, within
the permissions above. **It is not an audit, not assurance, and not a
statement that anything it does not list is fine.** The report includes a
short prioritised plan of what I would fix first and why. Those
recommendations are advisory; implementing them stays with you or the provider
you choose. I do not make changes to your tenant.

If I find something that cannot wait for the report — an active compromise, a
misused admin account — I pause, do only what is needed to confirm and
describe it, and call the person below before continuing.

**Urgent contact (name and phone):** ______________________

## 5. Where I stand

This is prototype tooling under active development, and I say so rather than
dress it up: **no professional liability insurance is currently in place.**
Formal terms follow a legal review; until then, this page is what we have both
agreed to, and it is deliberately narrow.

---

*fieldkit version:* ____________ · *tool and permission list:*
`github.com/Jon-Hauk/fieldkit` at that version · *operator:* Jon Hauk, Edmonton
