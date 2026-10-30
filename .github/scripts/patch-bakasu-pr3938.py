#!/usr/bin/env python3
"""Targeted OP15 Linux 6.12 BakaSU port of KernelSU PR #3938.

Only touches kernel/feature/selinux_hide.c in the selected BakaSU clone.
Keeps the original implementation for kernels older than 6.12.
Fail closed on upstream source layout drift; never silently skip a patch.
"""
from pathlib import Path
import sys

if len(sys.argv) != 2:
    raise SystemExit("Usage: patch-bakasu-pr3938.py /path/to/KernelSU/kernel/feature/selinux_hide.c")
path = Path(sys.argv[1]).resolve()
if path.name != 'selinux_hide.c' or path.parent.name != 'feature' or path.parent.parent.name != 'kernel':
    raise SystemExit(f"ERROR: Refusing unexpected source path: {path}")
source = path.read_text()
marker = 'BAKASU_PR3938_OP15_PORT'
if marker in source:
    raise SystemExit('ERROR: Port marker already exists. Expected a fresh BakaSU checkout.')

# Keep the existing upstream, backwards-compatible parsing helper unchanged.
# Add a separate helper for GKI 6.12 so no legacy BakaSU kernels are affected.
anchor = '/*\n * Caveat:  Mutates scontext.\n */\n'
if source.count(anchor) != 1:
    raise SystemExit('ERROR: Expected unique context parser anchor is missing or duplicated.')
helper = r'''/* BAKASU_PR3938_OP15_PORT: dedicated single-policy parser for GKI 6.12. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int ksu_pr3938_parse_context(struct policydb *pol, struct sidtab *sidtabp,
                                    char *scontext, struct context *ctx, u32 def_sid)
{
    struct role_datum *role;
    struct type_datum *typdatum;
    struct user_datum *usrdatum;
    char *scontextp, *p, oldc;
    int rc = -EINVAL;

    context_init(ctx);
    scontextp = scontext;
    p = scontextp;
    while (*p && *p != ':')
        p++;
    if (!*p)
        goto out;
    *p++ = '\0';
    usrdatum = symtab_search(&pol->p_users, scontextp);
    if (!usrdatum)
        goto out;
    ctx->user = usrdatum->value;

    scontextp = p;
    while (*p && *p != ':')
        p++;
    if (!*p)
        goto out;
    *p++ = '\0';
    role = symtab_search(&pol->p_roles, scontextp);
    if (!role)
        goto out;
    ctx->role = role->value;

    scontextp = p;
    while (*p && *p != ':')
        p++;
    oldc = *p;
    *p++ = '\0';
    typdatum = symtab_search(&pol->p_types, scontextp);
    if (!typdatum || typdatum->attribute)
        goto out;
    ctx->type = typdatum->value;

    rc = mls_context_to_sid(pol, oldc, p, ctx, sidtabp, def_sid);
    if (rc)
        goto out;
    rc = -EINVAL;
    if (!policydb_context_isvalid(pol, ctx))
        goto out;
    rc = 0;
out:
    if (rc)
        context_destroy(ctx);
    return rc;
}
#endif /* Linux 6.12+ */

'''
source = source.replace(anchor, helper + anchor, 1)

# Replace only the GKI 6.12 implementation of this function. Leave older
# versions byte-for-byte identical inside the #else conditional branch.
function_name = '__maybe_static int security_context_to_sid_with_policy('
if source.count(function_name) != 1:
    raise SystemExit('ERROR: Expected unique target function definition not found.')
start = source.index(function_name)
brace = source.find('\n{\n', start)
if brace < 0:
    raise SystemExit('ERROR: Target function opening brace not found.')
body_begin = brace + len('\n{\n')
end_marker = '\n}\n\n/*\n * Write the security context string representation'
body_end = source.find(end_marker, body_begin)
if body_end < 0:
    raise SystemExit('ERROR: Target function closing marker not found.')
legacy_body = source[body_begin:body_end]
required = ('string_to_context_struct(', 'kmemdup_nul(', 'rcu_read_lock();', 'sidtab_context_to_sid(')
if any(needle not in legacy_body for needle in required):
    raise SystemExit('ERROR: BakaSU context conversion layout changed; refusing to patch.')
new_body = r'''#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    /* On invalid contexts, do not consult the live policy. PR #3938. */
    struct selinux_policy *orig_policy;
    struct policydb *backup_db, *orig_policydb;
    struct sidtab *backup_tab, *orig_sidtab;
    char backup_stack[128] __aligned(sizeof(long));
    char live_stack[128] __aligned(sizeof(long));
    char *backup_copy, *live_copy = NULL;
    struct context backup_ctx, orig_ctx;
    int rc = 0, orig_rc = 0;
    u32 orig_sid = SECSID_NULL;

    if (!scontext_len)
        return -EINVAL;

    if (scontext_len < sizeof(backup_stack)) {
        backup_copy = backup_stack;
        memcpy(backup_copy, scontext, scontext_len);
        backup_copy[scontext_len] = '\0';
    } else {
        backup_copy = kmemdup_nul(scontext, scontext_len, gfp_flags);
        if (!backup_copy)
            return -ENOMEM;
    }
    *sid = SECSID_NULL;
    if (orig_sid_p)
        *orig_sid_p = SECSID_NULL;

    backup_db = &policy->policydb;
    backup_tab = policy->sidtab;
    rcu_read_lock();
    rc = ksu_pr3938_parse_context(backup_db, backup_tab, backup_copy,
                                   &backup_ctx, def_sid);
    if (!rc) {
#ifdef KSU_COMPAT_HAS_CONTEXT_ADD_HASH
        rc = context_add_hash(backup_db, &backup_ctx);
#endif
        if (!rc)
            rc = sidtab_context_to_sid(backup_tab, &backup_ctx, sid);
        context_destroy(&backup_ctx);
    }
    rcu_read_unlock();
    if (rc)
        goto out;

    if (scontext_len < sizeof(live_stack)) {
        live_copy = live_stack;
        memcpy(live_copy, scontext, scontext_len);
        live_copy[scontext_len] = '\0';
    } else {
        live_copy = kmemdup_nul(scontext, scontext_len, gfp_flags);
        if (!live_copy) {
            rc = -ENOMEM;
            goto out;
        }
    }

retry_live:
    orig_sid = SECSID_NULL;
    rcu_read_lock();
    orig_policy = rcu_dereference(selinux_state.policy);
    orig_policydb = &orig_policy->policydb;
    orig_sidtab = orig_policy->sidtab;
    orig_rc = ksu_pr3938_parse_context(orig_policydb, orig_sidtab,
                                        live_copy, &orig_ctx, def_sid);
    if (!orig_rc) {
#ifdef KSU_COMPAT_HAS_CONTEXT_ADD_HASH
        orig_rc = context_add_hash(orig_policydb, &orig_ctx);
#endif
        if (!orig_rc)
            orig_rc = sidtab_context_to_sid(orig_sidtab, &orig_ctx, &orig_sid);
        context_destroy(&orig_ctx);
    }
    rcu_read_unlock();
    if (orig_rc == -ESTALE) {
        memcpy(live_copy, scontext, scontext_len);
        live_copy[scontext_len] = '\0';
        goto retry_live;
    }
out:
    if (rc)
        orig_rc = rc;
    if (orig_rc_p)
        *orig_rc_p = orig_rc;
    if (orig_sid_p)
        *orig_sid_p = orig_sid;
    if (live_copy && live_copy != live_stack)
        kfree(live_copy);
    if (backup_copy != backup_stack)
        kfree(backup_copy);
    return rc;
#else /* Retain existing BakaSU implementation for older kernels. */
'''
source = source[:body_begin] + new_body + legacy_body + '\n#endif /* Linux 6.12+ PR3938 port */' + source[body_end:]
if source.count(marker) != 1 or source.count('ksu_pr3938_parse_context(') != 3:
    raise SystemExit('ERROR: Generated patch failed structural validation.')
path.write_text(source)
print(f'PASS: BakaSU PR3938 6.12-only port installed: {path}')
