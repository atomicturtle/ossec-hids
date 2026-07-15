/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Rootcheck decoder */

#include "config.h"
#include "shared.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"

#define ROOTCHECK_DIR    "/queue/rootcheck"

/* Local variables */
static char *rk_agent_ips[MAX_AGENTS];
static FILE *rk_agent_fps[MAX_AGENTS];
static int rk_err;
#ifndef WIN32
/* Table mutex: agent slot alloc / lookup. Per-agent mutex: FILE* I/O. */
static pthread_mutex_t rk_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rk_agent_mutex[MAX_AGENTS];
static int rk_agent_mutex_ready = 0;
#endif

/* Rootcheck decoder template (shared id/name/type). Per-thread copy holds fts. */
static OSDecoderInfo *rootcheck_dec_tmpl = NULL;
#ifndef WIN32
static __thread OSDecoderInfo rk_dec_tls;
static __thread int rk_dec_tls_ready = 0;
#endif

static OSDecoderInfo *rootcheck_decoder_for_event(void)
{
#ifndef WIN32
    if (!rk_dec_tls_ready && rootcheck_dec_tmpl) {
        rk_dec_tls = *rootcheck_dec_tmpl;
        rk_dec_tls_ready = 1;
    }
    return &rk_dec_tls;
#else
    return rootcheck_dec_tmpl;
#endif
}

/* Initialize the necessary information to process the rootcheck information */
void RootcheckInit()
{
    int i = 0;

    rk_err = 0;

    for (; i < MAX_AGENTS; i++) {
        rk_agent_ips[i] = NULL;
        rk_agent_fps[i] = NULL;
#ifndef WIN32
        os_mutex_init(&rk_agent_mutex[i], NULL);
#endif
    }
#ifndef WIN32
    rk_agent_mutex_ready = 1;
#endif

    /* Template decoder — workers use a TLS copy so fts is not shared. */
    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec_tmpl);
    rootcheck_dec_tmpl->id = getDecoderfromlist(ROOTCHECK_MOD);
    rootcheck_dec_tmpl->type = OSSEC_RL;
    rootcheck_dec_tmpl->name = ROOTCHECK_MOD;
    rootcheck_dec_tmpl->fts = 0;

    debug1("%s: RootcheckInit completed.", ARGV0);

    return;
}

/* Return the file pointer to be used */
static FILE *RK_File(const char *agent, int *agent_id)
{
    int i = 0;
    char rk_buf[OS_SIZE_1024 + 1];

    while (i < MAX_AGENTS && rk_agent_ips[i] != NULL) {
        if (strcmp(rk_agent_ips[i], agent) == 0) {
            /* Pointing to the beginning of the file */
            fseek(rk_agent_fps[i], 0, SEEK_SET);
            *agent_id = i;
            return (rk_agent_fps[i]);
        }

        i++;
    }

    /* If here, our agent wasn't found */
    if (i == MAX_AGENTS) {
        merror("%s: Unable to open rootcheck file. Increase MAX_AGENTS.", ARGV0);
        return (NULL);
    }

    /* If here, our agent wasn't found */
    rk_agent_ips[i] = strdup(agent);

    if (rk_agent_ips[i] != NULL) {
        snprintf(rk_buf, OS_SIZE_1024, "%s/%s", ROOTCHECK_DIR, agent);

        /* r+ to read and write. Do not truncate */
        rk_agent_fps[i] = fopen(rk_buf, "r+");
        if (!rk_agent_fps[i]) {
            /* Try opening with a w flag, file probably does not exist */
            rk_agent_fps[i] = fopen(rk_buf, "w");
            if (rk_agent_fps[i]) {
                fclose(rk_agent_fps[i]);
                rk_agent_fps[i] = fopen(rk_buf, "r+");
            }
        }
        if (!rk_agent_fps[i]) {
            merror(FOPEN_ERROR, ARGV0, rk_buf, errno, strerror(errno));

            free(rk_agent_ips[i]);
            rk_agent_ips[i] = NULL;

            return (NULL);
        }

        /* Return the opened pointer (the beginning of it) */
        fseek(rk_agent_fps[i], 0, SEEK_SET);
        *agent_id = i;
        return (rk_agent_fps[i]);
    }

    else {
        merror(MEM_ERROR, ARGV0, errno, strerror(errno));
        return (NULL);
    }

    return (NULL);
}

/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
static int DecodeRootcheck_with_fp(Eventinfo *lf, FILE *fp)
{
    char *tmpstr;
    char rk_buf[OS_SIZE_2048 + 1];
    fpos_t fp_pos;
    OSDecoderInfo *rk_dec = rootcheck_decoder_for_event();

    /* Zero rk_buf */
    rk_buf[0] = '\0';
    rk_buf[OS_SIZE_2048] = '\0';

    /* Get initial position */
    if (fgetpos(fp, &fp_pos) == -1) {
        merror("%s: Error handling rootcheck database (fgetpos).", ARGV0);
        return (0);
    }


    /* Reads the file and search for a possible entry */
    while (fgets(rk_buf, OS_SIZE_2048 - 1, fp) != NULL) {
        /* Ignore blank lines and lines with a comment */
        if (rk_buf[0] == '\n' || rk_buf[0] == '#') {
            if (fgetpos(fp, &fp_pos) == -1) {
                merror("%s: Error handling rootcheck database "
                       "(fgetpos2).", ARGV0);
                return (0);
            }
            continue;
        }

        /* Remove newline */
        tmpstr = strchr(rk_buf, '\n');
        if (tmpstr) {
            *tmpstr = '\0';
        }

        /* Old format without the time stamps */
        if (rk_buf[0] != '!') {
            /* Cannot use strncmp to avoid errors with crafted files */
            if (strcmp(lf->log, rk_buf) == 0) {
                rk_dec->fts = 0;
                lf->decoder_info = rk_dec;
                return (1);
            }
        }
        /* New format */
        else {
            /* Going past time: !1183431603!1183431603  (last, first seen) */
            tmpstr = rk_buf + 23;

            /* Matches, we need to upgrade last time saw */
            if (strcmp(lf->log, tmpstr) == 0) {
                if(fsetpos(fp, &fp_pos)) {
                    merror("%s: Error handling rootcheck database "
                           "(fsetpos).", ARGV0);
                    return (0);
                }
                fprintf(fp, "!%ld", (long int)lf->time);
                rk_dec->fts = 0;
                lf->decoder_info = rk_dec;
                return (1);
            }
        }

        /* Get current position */
        if (fgetpos(fp, &fp_pos) == -1) {
            merror("%s: Error handling rootcheck database (fgetpos3).", ARGV0);
            return (0);
        }
    }

    /* Add the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "!%ld!%ld %s\n", (long int)lf->time, (long int)lf->time, lf->log);
    fflush(fp);

    rk_dec->fts = 0;
    rk_dec->fts |= FTS_DONE;
    lf->decoder_info = rk_dec;
    return (1);
}

int DecodeRootcheck(Eventinfo *lf)
{
    int result;
    int agent_id = -1;
    FILE *fp;

#ifndef WIN32
    os_mutex_lock(&rk_table_mutex);
#endif
    fp = RK_File(lf->location, &agent_id);
    if (!fp) {
#ifndef WIN32
        os_mutex_unlock(&rk_table_mutex);
#endif
        merror("%s: Error handling rootcheck database.", ARGV0);
        rk_err++;
        return (0);
    }

#ifndef WIN32
    /* Lock the agent FILE before releasing the table (finer than global lock). */
    os_mutex_lock(&rk_agent_mutex[agent_id]);
    os_mutex_unlock(&rk_table_mutex);
#endif

    result = DecodeRootcheck_with_fp(lf, fp);

#ifndef WIN32
    os_mutex_unlock(&rk_agent_mutex[agent_id]);
#endif
    return result;
}

