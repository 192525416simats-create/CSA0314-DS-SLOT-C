#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET Socket;
#define close_socket closesocket
#define BAD_SOCKET INVALID_SOCKET
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
typedef int Socket;
#define close_socket close
#define BAD_SOCKET (-1)
#endif
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sqlite_api.h"
#include "dsa.h"

static sqlite3 *db;
static FILE *out;
static int uid, admin, response, seed_mode;
static char session[65], new_cookie[180];
static const char *notice;
static const char *categories[] = {"Electronics","Stationery","Accessories","Documents","Other"};
static int suggestions;

static sqlite3_stmt *query(const char *sql) {
    sqlite3_stmt *s = NULL;
    sqlite3_prepare_v2(db,sql,-1,&s,NULL);
    return s;
}
static void bind_text(sqlite3_stmt *s,int i,const char *v) {
    sqlite3_bind_text(s,i,v,-1,SQLITE_TRANSIENT);
}
static int run(sqlite3_stmt *s) {
    int ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}
static int sql(const char *s) { return sqlite3_exec(db,s,NULL,NULL,NULL)==SQLITE_OK; }
static const char *col(sqlite3_stmt *s,int i) {
    const unsigned char *v = sqlite3_column_text(s,i);
    return v ? (const char *)v : "";
}
static void esc(const char *s) {
    for (; *s; ++s) {
        switch (*s) {
        case '&': fputs("&amp;",out); break;
        case '<': fputs("&lt;",out); break;
        case '>': fputs("&gt;",out); break;
        case '"': fputs("&quot;",out); break;
        case 39: fputs("&#39;",out); break;
        default: fputc((unsigned char)*s,out);
        }
    }
}
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c-'0';
    if (c >= 'a' && c <= 'f') return c-'a'+10;
    if (c >= 'A' && c <= 'F') return c-'A'+10;
    return -1;
}
static void hex(char *dest,const unsigned char *src,size_t n) {
    for (size_t i=0;i<n;++i) sprintf(dest+i*2,"%02x",src[i]);
}
static int field(const char *form,const char *key,char *dest,size_t cap) {
    size_t keylen=strlen(key);
    dest[0]=0;
    for (const char *p=form; *p;) {
        const char *end=strchr(p,'&');
        if (!end) end=p+strlen(p);
        if ((size_t)(end-p)>keylen && !strncmp(p,key,keylen) && p[keylen]=='=') {
            size_t n=0;
            for (p+=keylen+1;p<end;++p) {
                int c=(unsigned char)*p;
                if (c=='+') c=' ';
                else if (c=='%') {
                    if (end-p<3 || hexval(p[1])<0 || hexval(p[2])<0) goto invalid;
                    c=16*hexval(p[1])+hexval(p[2]);
                    p+=2;
                }
                if (c<32 || c==127 || n+1>=cap) goto invalid;
                dest[n++]=(char)c;
            }
            dest[n]=0;
            return 1;
        }
        p=*end ? end+1 : end;
    }
    return 0;
invalid:
    dest[0]=0;
    return 0;
}
static int number(const char *form,const char *key) {
    char v[16], *end;
    if (!field(form,key,v,sizeof v)) return 0;
    long n=strtol(v,&end,10);
    return *end || n<1 || n>INT_MAX ? 0 : (int)n;
}
static int valid_date(const char *s) {
    static const int days[]={31,28,31,30,31,30,31,31,30,31,30,31};
    if (strlen(s)!=10 || s[4]!='-' || s[7]!='-') return 0;
    for (int i=0;i<10;++i) if (i!=4 && i!=7 && !isdigit((unsigned char)s[i])) return 0;
    int y=atoi(s),m=atoi(s+5),d=atoi(s+8);
    int leap=y%4==0 && (y%100!=0 || y%400==0);
    return y>=1900 && m>=1 && m<=12 && d>=1 && d<=days[m-1]+(m==2 && leap);
}
static int password_hash(const char *password,const unsigned char salt[16],char result[98]) {
    unsigned char digest[32];
    if (!PKCS5_PBKDF2_HMAC(password,(int)strlen(password),salt,16,600000,EVP_sha256(),32,digest))
        return 0;
    hex(result,salt,16);
    result[32]='$';
    hex(result+33,digest,32);
    return 1;
}
static int create_user(const char *email,const char *password,int role) {
    unsigned char salt[16];
    char digest[98];
    if (RAND_bytes(salt,sizeof salt)!=1 || !password_hash(password,salt,digest)) return 0;
    sqlite3_stmt *s=query("INSERT INTO users(email,password,admin) VALUES(?,?,?)");
    bind_text(s,1,email); bind_text(s,2,digest); sqlite3_bind_int(s,3,role);
    return run(s);
}
static int authenticate(const char *email,const char *password) {
    sqlite3_stmt *s=query("SELECT id,password FROM users WHERE email=?");
    bind_text(s,1,email);
    int id=0;
    if (sqlite3_step(s)==SQLITE_ROW && strlen(col(s,1))==97) {
        char digest[98];
        unsigned char salt[16];
        const char *stored=col(s,1);
        for (int i=0;i<16;++i)
            salt[i]=(unsigned char)(16*hexval(stored[i*2])+hexval(stored[i*2+1]));
        if (password_hash(password,salt,digest) && CRYPTO_memcmp(digest,stored,97)==0)
            id=sqlite3_column_int(s,0);
    }
    sqlite3_finalize(s);
    return id;
}
static void login(int id) {
    unsigned char bytes[32];
    char token[65];
    if (RAND_bytes(bytes,sizeof bytes)!=1) { notice="Could not start a session."; return; }
    hex(token,bytes,sizeof bytes);
    sqlite3_stmt *s=query("INSERT INTO sessions VALUES(?,?,unixepoch()+28800)");
    bind_text(s,1,token); sqlite3_bind_int(s,2,id);
    if (run(s)) {
        snprintf(new_cookie,sizeof new_cookie,"cf=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800",token);
        response=303;
    } else notice="Could not start a session.";
}
static void identify(const char *headers) {
    uid=admin=0;
    session[0]=0;
    const char *p=strstr(headers,"\r\nCookie:");
    if (!p) return;
    p+=9;
    while (*p==' ') ++p;
    const char *end=strstr(p,"\r\n");
    if (!end) end=p+strlen(p);
    while (p<end) {
        if (end-p>=67 && !strncmp(p,"cf=",3)) {
            int length=0;
            while (length<64 && hexval(p[3+length])>=0) ++length;
            if (length==64 && (p+67==end || p[67]==';')) {
                memcpy(session,p+3,64); session[64]=0;
                break;
            }
        }
        while (p<end && *p!=';') ++p;
        if (p<end) ++p;
        while (p<end && *p==' ') ++p;
    }
    if (!*session) return;
    sqlite3_stmt *s=query("SELECT u.id,u.admin FROM sessions s JOIN users u ON u.id=s.uid WHERE s.token=? AND s.expires>unixepoch()");
    bind_text(s,1,session);
    if (sqlite3_step(s)==SQLITE_ROW) { uid=sqlite3_column_int(s,0); admin=sqlite3_column_int(s,1); }
    sqlite3_finalize(s);
}
static void location_options(int selected) {
    sqlite3_stmt *s=query("SELECT id,name FROM locations ORDER BY id");
    while (sqlite3_step(s)==SQLITE_ROW) {
        fprintf(out,"<option value=\"%d\"%s>",sqlite3_column_int(s,0),
            sqlite3_column_int(s,0)==selected?" selected":""); esc(col(s,1)); fputs("</option>",out);
    }
    sqlite3_finalize(s);
}
static int location_exists(int id) {
    if (id<=0 || id>=PLACES) return 0;
    sqlite3_stmt *s=query("SELECT 1 FROM locations WHERE id=?");
    sqlite3_bind_int(s,1,id);
    int exists=sqlite3_step(s)==SQLITE_ROW;
    sqlite3_finalize(s);
    return exists;
}
static void print_location(int id) {
    sqlite3_stmt *s=query("SELECT name FROM locations WHERE id=?");
    sqlite3_bind_int(s,1,id);
    if (sqlite3_step(s)==SQLITE_ROW) esc(col(s,0));
    sqlite3_finalize(s);
}
static void report_insert(const char *form) {
    char type[8],name[81],cat[41],colour[41],date[11],details[501];
    int place=number(form,"place"), category_ok=0;
    field(form,"type",type,sizeof type); field(form,"name",name,sizeof name);
    field(form,"category",cat,sizeof cat); field(form,"colour",colour,sizeof colour);
    field(form,"date",date,sizeof date); field(form,"details",details,sizeof details);
    for (size_t i=0;i<sizeof categories/sizeof *categories;++i)
        if (!strcmp(cat,categories[i])) category_ok=1;
    if ((strcmp(type,"Lost") && strcmp(type,"Found")) || !*name || !category_ok ||
        !*colour || !valid_date(date) || !location_exists(place) || !*details) {
        notice="Check all report fields and enter a valid date."; return;
    }
    sqlite3_stmt *s=query("INSERT INTO reports(uid,type,name,category,colour,place,event_date,details) VALUES(?,?,?,?,?,?,?,?)");
    sqlite3_bind_int(s,1,uid); bind_text(s,2,type); bind_text(s,3,name); bind_text(s,4,cat);
    bind_text(s,5,colour); sqlite3_bind_int(s,6,place); bind_text(s,7,date); bind_text(s,8,details);
    notice=run(s) ? "Report saved." : "Could not save report.";
}
static void claim_insert(const char *form) {
    char evidence[501];
    if (!field(form,"evidence",evidence,sizeof evidence) || !*evidence) { notice="Enter ownership evidence."; return; }
    sqlite3_stmt *s=query("INSERT INTO claims(report,uid,evidence) SELECT id,?,? FROM reports WHERE id=? AND uid<>? AND type='Found' AND status='Open'");
    sqlite3_bind_int(s,1,uid); bind_text(s,2,evidence);
    sqlite3_bind_int(s,3,number(form,"id")); sqlite3_bind_int(s,4,uid);
    notice=run(s) && sqlite3_changes(db)==1 ? "Claim submitted." : "Claim unavailable or already submitted.";
}
static void decide(const char *form) {
    if (!admin) { response=403; notice="Administrator access is required."; return; }
    char action[12];
    int id=number(form,"id");
    field(form,"action",action,sizeof action);
    int approve=!strcmp(action,"approve");
    if ((!approve && strcmp(action,"reject")) || !id) { notice="Invalid decision."; return; }
    if (!sql("BEGIN IMMEDIATE")) { notice="Database is busy. Try again."; return; }
    sqlite3_stmt *s=query("UPDATE claims SET status=? WHERE id=? AND status='Pending' AND report IN (SELECT id FROM reports WHERE status='Open')");
    bind_text(s,1,approve?"Approved":"Rejected"); sqlite3_bind_int(s,2,id);
    int ok=run(s) && sqlite3_changes(db)==1;
    if (ok && approve) {
        s=query("UPDATE reports SET status='Recovered' WHERE id=(SELECT report FROM claims WHERE id=?) AND status='Open'");
        sqlite3_bind_int(s,1,id);
        ok=run(s) && sqlite3_changes(db)==1;
        if (ok) {
            s=query("UPDATE claims SET status='Rejected' WHERE report=(SELECT report FROM claims WHERE id=?) AND status='Pending'");
            sqlite3_bind_int(s,1,id);
            ok=run(s);
        }
    }
    if (ok && sql("COMMIT")) notice="Decision recorded.";
    else { sql("ROLLBACK"); notice="This claim is no longer pending or could not be updated."; }
}

static void nav_link(const char *href,const char *active,const char *icon,const char *label) {
    fprintf(out,"<a href=\"%s\"%s><span aria-hidden=true>%s</span>%s</a>",
        href,!strcmp(href,active)?" aria-current=page":"",icon,label);
}
static void page_start(const char *path) {
    fputs("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width, initial-scale=1\">"
        "<title>CampusFind</title><link rel=stylesheet href=/style.css><script defer src=/app.js></script>"
        "<body><a class=skip-link href=#main>Skip to content</a><header class=shell-nav>"
        "<a class=brand href=/><span aria-hidden=true>CF</span>CampusFind</a>",out);
    if (uid) {
        const char *active=!strcmp(path,"/item")?"/":!strcmp(path,"/claim")?"/mine":!strcmp(path,"/decision")?"/review":path;
        fputs("<nav aria-label=\"Main navigation\">",out);
        nav_link("/",active,"▦","Dashboard");
        nav_link("/report",active,"＋","Report item");
        nav_link("/mine",active,"≡","My activity");
        nav_link("/route",active,"↗","Campus routes");
        if (admin) nav_link("/review",active,"✓","Review claims");
        fputs("</nav>",out);
    }
    fputs("</header><div class=workspace><div class=topbar><span>Campus lost and found</span><div class=account-actions>",out);
    if (uid) fprintf(out,"<span class=role>%s</span><form action=/logout method=post><button class=secondary>Sign out</button></form>",
        admin?"Administrator":"Member");
    fputs("</div></div><main id=main>",out);
    if (notice) { fputs("<p class=notice role=status>",out); esc(notice); fputs("</p>",out); }
}
static void account_page(void) {
    fputs("<h1>Campus lost and found</h1><p>Report an item, find possible matches, and arrange collection.</p><div class=grid>"
        "<section><h2>Sign in</h2><form action=/login method=post><label>Email<input required type=email name=email maxlength=120></label><label>Password<input required type=password name=password maxlength=128></label><button>Sign in</button></form></section>"
        "<section><h2>Create an account</h2><form action=/register method=post><label>Email<input required type=email name=email maxlength=120></label><label>Password<input required type=password name=password minlength=8 maxlength=128></label><button>Register</button></form></section></div>",out);
}
static void report_page(void) {
    fputs("<h1>Report an item</h1><section><form method=post action=/report><label>Report type<select name=type><option>Lost</option><option>Found</option></select></label><label>Item name<input required name=name maxlength=80></label><label>Category<select name=category>",out);
    for (size_t i=0;i<sizeof categories/sizeof *categories;++i) fprintf(out,"<option>%s</option>",categories[i]);
    fputs("</select></label><label>Colour<input name=colour required maxlength=40></label><label>Campus location<select name=place>",out);
    location_options(0);
    fputs("</select></label><label>Date<input type=date required name=date></label><label>Public description<input name=details required maxlength=500></label><button>Save report</button></form></section>",out);
}

static Index *load_index(void) {
    Index *index=index_new();
    if (!index) return NULL;
    sqlite3_stmt *s=query("SELECT id,type,name,category,colour,place,event_date FROM reports ORDER BY id");
    int rc;
    while ((rc=sqlite3_step(s))==SQLITE_ROW) {
        Report r={0};
        r.id=sqlite3_column_int(s,0); r.place=sqlite3_column_int(s,5);
        snprintf(r.type,sizeof r.type,"%s",col(s,1)); snprintf(r.name,sizeof r.name,"%s",col(s,2));
        snprintf(r.category,sizeof r.category,"%s",col(s,3)); snprintf(r.colour,sizeof r.colour,"%s",col(s,4));
        snprintf(r.date,sizeof r.date,"%s",col(s,6));
        if (!valid_date(r.date) || !index_add(index,&r)) { index_free(index); index=NULL; break; }
    }
    sqlite3_finalize(s);
    if (index && rc!=SQLITE_DONE) { index_free(index); return NULL; }
    return index;
}
static void print_link(const Report *r) {
    fprintf(out,"<a href=\"/item?id=%d\">#%d ",r->id,r->id); esc(r->name); fputs("</a>",out);
}
static void prefix_result(const Report *r) {
    if (suggestions++>=30) return;
    fputs("<li>",out); print_link(r); fprintf(out," <small>%s</small></li>",r->type);
}
static void dashboard_summary(void) {
    sqlite3_stmt *s=query("SELECT count(*),"
        "count(CASE WHEN type='Lost' AND status='Open' THEN 1 END),"
        "count(CASE WHEN type='Found' AND status='Open' THEN 1 END),"
        "count(CASE WHEN status='Recovered' THEN 1 END) FROM reports");
    static const char *names[]={"All reports","Open lost","Open found","Recovered"};
    static const char *links[]={"#reports","?type=Lost&amp;status=Open#reports",
        "?type=Found&amp;status=Open#reports","?status=Recovered#reports"};
    static const char *icons[]={"▤","⌕","◇","✓"};
    fputs("<div class=metrics>",out);
    if (sqlite3_step(s)==SQLITE_ROW)
        for (int i=0;i<4;++i)
            fprintf(out,"<a class=\"metric metric-%d\" href=\"/%s\"><span>%s</span><strong>%d</strong>"
                "<small>%s</small><i aria-hidden=true>↗</i></a>",i,links[i],names[i],sqlite3_column_int(s,i),icons[i]);
    fputs("</div>",out);
    sqlite3_finalize(s);
}

static void dashboard_insights(const char *date) {
    int lost[14]={0},found[14]={0};
    char days[14][11]={{0}},latest[11]={0};
    sqlite3_stmt *s=query("WITH RECURSIVE days(d,i) AS ("
        "SELECT date(coalesce(max(event_date),date('now')),'-13 days'),0 FROM reports "
        "UNION ALL SELECT date(d,'+1 day'),i+1 FROM days WHERE i<13) "
        "SELECT d,i,count(CASE WHEN r.type='Lost' THEN 1 END),"
        "count(CASE WHEN r.type='Found' THEN 1 END) FROM days "
        "LEFT JOIN reports r ON r.event_date=d GROUP BY d,i ORDER BY i");
    while (sqlite3_step(s)==SQLITE_ROW) {
        int i=sqlite3_column_int(s,1);
        if (i<0 || i>=14) continue;
        snprintf(days[i],sizeof days[i],"%s",col(s,0));
        lost[i]=sqlite3_column_int(s,2);
        found[i]=sqlite3_column_int(s,3);
    }
    sqlite3_finalize(s);
    snprintf(latest,sizeof latest,"%s",*date?date:days[13]);
    fputs("<div class=insights><section class=trend><div class=panel-head><div><h2>Report activity</h2>"
        "<p>By incident date · Latest 14 days</p></div><div class=period hidden aria-label=\"Chart period\">"
        "<button type=button data-period=7 aria-pressed=true>7 days</button>"
        "<button type=button data-period=14 aria-pressed=false>14 days</button></div></div>"
        "<p class=legend><span>Lost</span><span>Found</span></p>"
        "<div class=plot hidden><canvas aria-label=\"Lost and found reports by date\" role=img></canvas></div>"
        "<p class=chart-note role=status hidden></p><details class=chart-data open><summary>Daily totals</summary>"
        "<table><thead><tr><th scope=col>Date</th><th scope=col>Lost</th><th scope=col>Found</th></tr></thead><tbody>",out);
    for (int i=0;i<14;++i) if (days[i][0])
        fprintf(out,"<tr><td>%s</td><td>%d</td><td>%d</td></tr>",days[i],lost[i],found[i]);
    fputs("</tbody></table></details></section>",out);

    fputs("<section class=breakdown><h2>Report categories</h2><p>All submitted reports</p>",out);
    s=query("SELECT category,count(*),(SELECT count(*) FROM reports) FROM reports "
        "GROUP BY category ORDER BY count(*) DESC,category");
    int rows=0;
    while (sqlite3_step(s)==SQLITE_ROW) {
        int n=sqlite3_column_int(s,1),total=sqlite3_column_int(s,2);
        fputs("<div class=category><span>",out); esc(col(s,0));
        fprintf(out,"</span><strong>%d</strong><progress aria-label=\"Report count in ",n); esc(col(s,0));
        fprintf(out,"\" value=%d max=%d></progress></div>",n,total);
        ++rows;
    }
    if (!rows) fputs("<p>No reports yet.</p>",out);
    sqlite3_finalize(s);
    fputs("</section><section class=calendar><h2>Report calendar</h2><p>Choose a date to filter reports.</p>"
        "<div class=calendar-widget hidden data-date=\"",out);
    esc(latest);
    fputs("\"><div class=calendar-nav><button type=button class=secondary data-month=-1 aria-label=\"Previous month\">‹</button>"
        "<strong aria-live=polite></strong><button type=button class=secondary data-month=1 aria-label=\"Next month\">›</button>"
        "</div><div class=calendar-grid></div></div><form class=calendar-form action=/#reports>"
        "<label>Report date <input type=date name=date required value=\"",out);
    esc(date);
    fputs("\"></label><button>Filter date</button></form></section></div>",out);
}

static void dashboard(const char *form,int mine) {
    char prefix[81],type[8],status[12],date[11];
    field(form,"q",prefix,sizeof prefix);
    field(form,"type",type,sizeof type);
    field(form,"status",status,sizeof status);
    field(form,"date",date,sizeof date);
    if (strcmp(type,"Lost") && strcmp(type,"Found")) type[0]=0;
    if (strcmp(status,"Open") && strcmp(status,"Recovered")) status[0]=0;
    if (!valid_date(date)) date[0]=0;
    if (*prefix) type[0]=status[0]=date[0]=0;
    fprintf(out,"<div class=page-title><div><h1>%s</h1><p>%s</p></div><a class=primary href=/report>＋ New report</a></div>",
        mine?"My activity":"Lost and found dashboard",
        mine?"Your reports and claim decisions.":"Search campus reports, track recoveries, and find where to collect an item.");
    if (!mine) {
        dashboard_summary();
        if (!*prefix && !*type && !*status) dashboard_insights(date);
        fputs("<section class=search-tools><form action=/#reports><label>Search item names<input name=q maxlength=80 "
            "placeholder=\"Try Lab or Transcript\" value=\"",out);
        esc(prefix);
        fputs("\"></label><button>Search</button></form><form action=/item><label>Report ID"
            "<input name=id type=number min=1 required placeholder=\"e.g. 2\"></label><button class=secondary>Look up ID</button>"
            "</form></section>",out);
    }

    fputs("<section class=reports id=reports><div class=panel-head><div><h2>",out);
    fputs(*prefix&&!mine?"Prefix search results":mine?"My reports":"Campus reports",out);
    fputs("</h2>",out);
    if (!mine && (*type || *status || *date || *prefix)) {
        fputs("<p class=filter-label>Filter",out);
        if (*prefix) { fputs(" · Name starts with ",out); esc(prefix); }
        if (*type) { fputs(" · ",out); esc(type); }
        if (*status) { fputs(" · ",out); esc(status); }
        if (*date) { fputs(" · ",out); esc(date); }
        fputs("</p>",out);
    }
    fputs("</div>",out);
    if (!mine)
        fprintf(out,"<nav class=filters aria-label=\"Report type\"><a href=/#reports%s>All</a>"
            "<a href=\"/?type=Lost#reports\"%s>Lost</a><a href=\"/?type=Found#reports\"%s>Found</a></nav>",
            (!*prefix && !*date && !*status && !*type)?" aria-current=true":"",
            !strcmp(type,"Lost")?" aria-current=true":"",!strcmp(type,"Found")?" aria-current=true":"");
    fputs("</div>",out);
    if (*prefix && !mine) {
        Index *idx=load_index();
        suggestions=0;
        fputs("<ul class=search-results>",out);
        if (idx) index_prefix(idx,prefix,prefix_result);
        fputs("</ul>",out);
        if (!suggestions) fputs(idx?"<p>No matching names.</p>":"<p>Search index unavailable.</p>",out);
        if (suggestions>30) fputs("<p>Showing the first 30 matches.</p>",out);
        index_free(idx);
        fputs("</section>",out);
        return;
    }
    sqlite3_stmt *s=query("SELECT r.id,r.name,r.type,r.status,l.name,r.event_date,r.category FROM reports r "
        "JOIN locations l ON l.id=r.place WHERE (?1=0 OR r.uid=?2) AND (?3='' OR r.type=?3) "
        "AND (?4='' OR r.status=?4) AND (?5='' OR r.event_date=?5) "
        "ORDER BY r.id DESC");
    sqlite3_bind_int(s,1,mine);
    sqlite3_bind_int(s,2,uid);
    bind_text(s,3,type);
    bind_text(s,4,status);
    bind_text(s,5,date);
    fputs("<div class=report-scroll tabindex=0 role=region aria-label=\"Report records\">"
        "<table class=report-table><thead><tr><th scope=col>Item</th><th scope=col>Type</th>"
        "<th scope=col>Location</th><th scope=col>Date</th><th scope=col>Status</th></tr></thead><tbody>",out);
    int count=0;
    while (sqlite3_step(s)==SQLITE_ROW) {
        ++count;
        int id=sqlite3_column_int(s,0);
        fprintf(out,"<tr><th scope=row><a href=\"/item?id=%d\">",id); esc(col(s,1));
        fprintf(out,"</a><small>#%d · ",id); esc(col(s,6));
        fprintf(out,"</small></th><td><span class=\"pill %s\">%s</span></td><td>",
            !strcmp(col(s,2),"Lost")?"lost":"found",col(s,2));
        esc(col(s,4)); fputs("</td><td>",out); esc(col(s,5));
        fprintf(out,"</td><td><span class=\"pill %s\">%s</span></td></tr>",
            !strcmp(col(s,3),"Recovered")?"recovered":"open",col(s,3));
    }
    if (!count) fputs("<tr><td colspan=5>No reports match this view.</td></tr>",out);
    fputs("</tbody></table></div></section>",out);
    sqlite3_finalize(s);
    if (!mine) return;

    fputs("<section><h2>My claims</h2>",out);
    s=query("SELECT c.report,r.name,c.status FROM claims c JOIN reports r ON r.id=c.report WHERE c.uid=? ORDER BY c.id DESC");
    sqlite3_bind_int(s,1,uid);
    count=0;
    while (sqlite3_step(s)==SQLITE_ROW) {
        ++count;
        fprintf(out,"<p><a href=\"/item?id=%d\">",sqlite3_column_int(s,0)); esc(col(s,1));
        fprintf(out,"</a> · %s</p>",col(s,2));
    }
    if (!count) fputs("<p>No claims yet.</p>",out);
    fputs("</section>",out);
    sqlite3_finalize(s);
}
static void matches(const Index *idx,const Report *r) {
    sqlite3_stmt *s=query("SELECT id FROM reports WHERE status='Open' AND type<>?");
    bind_text(s,1,r->type);
    size_t n=0,cap=0;
    Match *items=NULL;
    int failed=0, rc;
    while ((rc=sqlite3_step(s))==SQLITE_ROW) {
        const Report *candidate=index_lookup(idx,sqlite3_column_int(s,0));
        if (!candidate) continue;
        if (n==cap) {
            size_t next=cap?cap*2:16;
            Match *larger=realloc(items,next*sizeof *items);
            if (!larger) { failed=1; break; }
            cap=next; items=larger;
        }
        items[n++]=(Match){candidate,match_score(r,candidate)};
    }
    sqlite3_finalize(s);
    Match *scratch=n>1?malloc(n*sizeof *scratch):NULL;
    fputs("<h2>Ranked potential matches</h2>",out);
    if (failed || rc!=SQLITE_DONE || (n>1 && !scratch)) fputs("<p>Matches are unavailable.</p>",out);
    else if (!n) fputs("<p>No open reports of the opposite type.</p>",out);
    else {
        merge_matches(items,scratch,n);
        fputs("<ol class=rank>",out);
        for (size_t i=0;i<n && i<12;++i) {
            int score=items[i].score;
            fputs("<li>",out); print_link(items[i].report);
            fprintf(out," <strong>%d/100</strong> <small>%s</small></li>",score,score>=80?"High priority":score>=60?"Possible":"Low priority");
        }
        fputs("</ol>",out);
    }
    free(items); free(scratch);
}
static void item_page(const char *form) {
    Index *idx=load_index();
    if (!idx) { fputs("<h1>Report lookup unavailable</h1>",out); return; }
    const Report *r=index_lookup(idx,number(form,"id"));
    if (!r) { response=404; fputs("<h1>Report not found</h1>",out); index_free(idx); return; }
    sqlite3_stmt *s=query("SELECT details,status,uid FROM reports WHERE id=?");
    sqlite3_bind_int(s,1,r->id);
    if (sqlite3_step(s)!=SQLITE_ROW) { sqlite3_finalize(s); index_free(idx); return; }
    int open=!strcmp(col(s,1),"Open"), owner=sqlite3_column_int(s,2)==uid;
    fprintf(out,"<section><small>Report #%d · %s · %s</small><h1>",r->id,r->type,col(s,1));
    esc(r->name); fputs("</h1><p>",out); esc(r->category); fputs(" · ",out); esc(r->colour);
    fputs(" · ",out); esc(r->date); fputs(" · ",out); print_location(r->place);
    fputs("</p><p>",out); esc(col(s,0));
    fprintf(out,"</p><a href=\"/route?end=%d\">Directions to report location</a></section>",r->place);
    sqlite3_finalize(s);
    if (open) matches(idx,r);
    if (open && !owner && !strcmp(r->type,"Found"))
        fprintf(out,"<section><h2>Claim this item</h2><form action=/claim method=post><input type=hidden name=id value=%d><label>Private ownership evidence<input required name=evidence maxlength=500></label><button>Submit claim</button></form></section>",r->id);
    index_free(idx);
}

typedef struct Claim {
    int id, report;
    char item[81], evidence[501];
    struct Claim *next;
} Claim;
static void review(void) {
    if (!admin) { response=403; fputs("<h1>Administrator access is required</h1>",out); return; }
    fputs("<h1>Pending claims</h1><p>Review ownership evidence in submission order.</p>",out);
    sqlite3_stmt *s=query("SELECT c.id,c.report,r.name,c.evidence FROM claims c JOIN reports r ON r.id=c.report WHERE c.status='Pending' ORDER BY c.id");
    Claim *first=NULL,*last=NULL;
    int rc;
    while ((rc=sqlite3_step(s))==SQLITE_ROW) {
        Claim *claim=calloc(1,sizeof *claim);
        if (!claim) break;
        claim->id=sqlite3_column_int(s,0); claim->report=sqlite3_column_int(s,1);
        snprintf(claim->item,sizeof claim->item,"%s",col(s,2));
        snprintf(claim->evidence,sizeof claim->evidence,"%s",col(s,3));
        if (last) last->next=claim;
        else first=claim;
        last=claim;
    }
    sqlite3_finalize(s);
    if (rc!=SQLITE_DONE) fputs("<p>Could not load the full queue.</p>",out);
    else if (!first) fputs("<p>No pending claims.</p>",out);
    while (first) {
        Claim *claim=first;
        first=claim->next;
        fprintf(out,"<section><h2><a href=\"/item?id=%d\">",claim->report); esc(claim->item);
        fputs("</a></h2><p>",out); esc(claim->evidence);
        fprintf(out,"</p><form action=/decision method=post data-confirm><input type=hidden name=id value=%d><div class=actions><button name=action value=approve>Approve</button><button class=secondary name=action value=reject>Reject</button></div></form></section>",claim->id);
        free(claim);
    }
}
static void route_page(const char *form) {
    int start=number(form,"start"),end=number(form,"end");
    fputs("<h1>Campus walking routes</h1><p>Demonstration locations and distances.</p><section><form class=route-form action=/route><label>Start<select name=start>",out);
    location_options(start);
    fputs("</select></label><label>Destination<select name=end>",out);
    location_options(end);
    fputs("</select></label><button>Find shortest route</button></form></section>",out);
    if (!start && !end) return;
    if (!start && end) return;
    if (!location_exists(start) || !location_exists(end)) { fputs("<p>Choose two valid locations.</p>",out); return; }
    int graph[PLACES][PLACES]={{0}},path[PLACES],distance;
    sqlite3_stmt *s=query("SELECT a,b,metres FROM edges");
    int rc;
    while ((rc=sqlite3_step(s))==SQLITE_ROW) {
        int a=sqlite3_column_int(s,0),b=sqlite3_column_int(s,1),w=sqlite3_column_int(s,2);
        if (a>0 && a<PLACES && b>0 && b<PLACES && w>0) graph[a][b]=graph[b][a]=w;
    }
    sqlite3_finalize(s);
    if (rc!=SQLITE_DONE) { fputs("<p>Campus map unavailable.</p>",out); return; }
    int n=shortest(graph,start,end,path,&distance);
    if (!n) { fputs("<p>No walking route connects these locations.</p>",out); return; }
    fprintf(out,"<section class=route-result><h2>Shortest route · %d m</h2><ol class=route-stops>",distance);
    for (int i=0;i<n;++i) { fputs("<li>",out); print_location(path[i]); fputs("</li>",out); }
    fputs("</ol></section>",out);
}

static void dispatch(const char *method,const char *path,const char *form) {
    if (!strcmp(method,"POST")) {
        if (!strcmp(path,"/login") || !strcmp(path,"/register")) {
            char email[121],password[129];
            field(form,"email",email,sizeof email); field(form,"password",password,sizeof password);
            if (!strcmp(path,"/login")) {
                int id=authenticate(email,password);
                if (id) login(id);
                else notice="Email or password is incorrect.";
            } else if (!*email || !strchr(email,'@') || strchr(email,' ') || strlen(password)<8)
                notice="Enter an email and a password of at least eight characters.";
            else notice=create_user(email,password,0) ? "Account created. Sign in to continue." : "Could not register this email.";
        } else if (!uid) { response=403; notice="Sign in to continue."; }
        else if (!strcmp(path,"/report")) report_insert(form);
        else if (!strcmp(path,"/claim")) claim_insert(form);
        else if (!strcmp(path,"/decision")) decide(form);
        else if (!strcmp(path,"/logout")) {
            sqlite3_stmt *s=query("DELETE FROM sessions WHERE token=?");
            bind_text(s,1,session);
            if (run(s)) {
                strcpy(new_cookie,"cf=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
                response=303;
            } else notice="Could not sign out. Try again.";
        } else response=404;
    }
    if (response==303) return;
    page_start(path);
    if (!uid) account_page();
    else if (!strcmp(path,"/report")) report_page();
    else if (!strcmp(path,"/item")) item_page(form);
    else if (!strcmp(path,"/mine") || !strcmp(path,"/claim")) dashboard("",1);
    else if (!strcmp(path,"/route")) route_page(form);
    else if (!strcmp(path,"/review") || !strcmp(path,"/decision")) review();
    else if (!strcmp(path,"/")) dashboard(form,0);
    else if (!strcmp(path,"/login") || !strcmp(path,"/register") || !strcmp(path,"/logout")) dashboard("",0);
    else { response=404; fputs("<h1>Page not found</h1>",out); }
    fputs("</main><footer>CampusFind · Data Structures Capstone</footer></div></body></html>",out);
}

static int header(const char *headers,const char *name,char *dest,size_t cap) {
    const char *p=strstr(headers,"\r\n");
    size_t len=strlen(name);
    if (!p) return 0;
    for (p+=2; *p;) {
        const char *end=strstr(p,"\r\n");
        if (!end) end=p+strlen(p);
        const char *colon=memchr(p,':',(size_t)(end-p));
        if (colon && (size_t)(colon-p)==len) {
            size_t i=0;
            while (i<len && tolower((unsigned char)p[i])==tolower((unsigned char)name[i])) ++i;
            if (i==len) {
                p=colon+1;
                while (p<end && (*p==' ' || *p=='\t')) ++p;
                if ((size_t)(end-p)>=cap) return 0;
                memcpy(dest,p,(size_t)(end-p)); dest[end-p]=0;
                return 1;
            }
        }
        p=*end ? end+2 : end;
    }
    return 0;
}

static int send_all(Socket client,const char *data,int size) {
    while (size>0) {
        int n=send(client,data,size,0);
        if (n<=0) return 0;
        data+=n; size-=n;
    }
    return 1;
}
static void send_page(Socket client,FILE *body,int code,const char *mime) {
    const char *reason=code==200?"OK":code==303?"See Other":code==403?"Forbidden":code==404?"Not Found":"Bad Request";
    char h[1024],buf[4096];
    fseek(body,0,SEEK_END);
    long len=ftell(body);
    rewind(body);
    int n=snprintf(h,sizeof h,"HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %ld\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'\r\n%s%s%s%s\r\n",
        code,reason,mime,len,code==303?"Location: /\r\n":"",*new_cookie?"Set-Cookie: ":"",new_cookie,*new_cookie?"\r\n":"");
    if (n>0 && (size_t)n<sizeof h && send_all(client,h,n))
        while ((n=(int)fread(buf,1,sizeof buf,body))>0 && send_all(client,buf,n)) {}
}
static void serve(Socket client,int port) {
    char data[16385]={0}, method[8], target[2048], origin[128], expected[64], host[64], content[32], type[120];
    char *separator=NULL;
    size_t used=0;
    new_cookie[0]=0; notice=NULL; response=200;
    out=tmpfile();
    if (!out) return;
    while (used<sizeof data-1 && !separator) {
        int n=recv(client,data+used,(int)(sizeof data-1-used),0);
        if (n<=0) goto bad;
        used+=(size_t)n; data[used]=0;
        separator=strstr(data,"\r\n\r\n");
    }
    if (!separator || sscanf(data,"%7s %2047s",method,target)!=2 || *target!='/') goto bad;
    char *body=separator+4;
    *separator=0;
    snprintf(expected,sizeof expected,"127.0.0.1:%d",port);
    if (!header(data,"Host",host,sizeof host) || strcmp(host,expected)) goto bad;
    char *form=strchr(target,'?');
    if (form) *form++=0;
    else form="";
    if (!strcmp(method,"POST")) {
        snprintf(expected,sizeof expected,"http://127.0.0.1:%d",port);
        if (!header(data,"Origin",origin,sizeof origin) || strcmp(origin,expected)) {
            fputs("Request origin was rejected.",out);
            send_page(client,out,403,"text/plain; charset=utf-8");
            goto done;
        }
        if (!header(data,"Content-Type",type,sizeof type) || strcmp(type,"application/x-www-form-urlencoded")
            || !header(data,"Content-Length",content,sizeof content)) goto bad;
        char *end;
        long length=strtol(content,&end,10);
        if (*end || length<0 || length>8192 || (size_t)(body-data)+length>=sizeof data) goto bad;
        size_t total=(size_t)(body-data)+(size_t)length;
        while (used<total) {
            int n=recv(client,data+used,(int)(total-used),0);
            if (n<=0) goto bad;
            used+=(size_t)n;
        }
        data[total]=0;
        if (strlen(body)!=(size_t)length) goto bad;
        form=body;
    } else if (strcmp(method,"GET")) goto bad;
    if (!strcmp(method,"GET") && (!strcmp(target,"/style.css") || !strcmp(target,"/app.js"))) {
        int css=!strcmp(target,"/style.css");
        FILE *asset=fopen(css?"public/style.css":"public/app.js","rb");
        if (!asset) { response=404; goto done; }
        send_page(client,asset,200,css?"text/css; charset=utf-8":"text/javascript; charset=utf-8");
        fclose(asset);
        goto done;
    }
    /* Normalize the Cookie field before session lookup. */
    char cookie[4096], normalized[4128];
    if (header(data,"Cookie",cookie,sizeof cookie)) {
        snprintf(normalized,sizeof normalized,"Request\r\nCookie: %s",cookie);
        identify(normalized);
    } else identify("");
    dispatch(method,target,form);
    send_page(client,out,response,"text/html; charset=utf-8");
    goto done;
bad:
    fputs("Use the local CampusFind URL and send a valid request.",out);
    send_page(client,out,400,"text/plain; charset=utf-8");
done:
    fclose(out);
}

typedef struct {
    const char *old_name, *name, *category, *colour, *description;
    int day;
} DemoItem;

static const DemoItem demo_items[]={
    {"Water bottle","Lab record file","Documents","Blue","A hardbound electronics lab record with a blue spine and a circuit diagram on the cover.",20},
    {"Scientific calculator","Sealed transcript envelope","Documents","Cream","A sealed campus transcript envelope with a blank demonstration reference label.",20},
    {"Lab notebook","Project proposal folder","Documents","Green","A green folder with a printed capstone proposal and blank review sheets.",18},
    {"USB drive","Survey dataset USB drive","Electronics","Black","A black USB drive with a yellow project tag.",19},
    {"Campus ID card","Workshop participation certificate","Documents","White","A workshop certificate in a clear sleeve with a folded corner.",16},
    {"Umbrella","Course registration printout","Documents","White","A folded course registration printout in a plain envelope.",18},
    {"Wireless earbuds","Internship offer packet","Documents","Brown","A brown folder containing fictional internship paperwork.",20},
    {"Pencil case","Research consent forms","Documents","Purple","A purple folder with blank classroom research consent forms.",15},
    {"Laptop sleeve","Fieldwork survey binder","Documents","Grey","A grey ring binder with sample observation sheets and index tabs.",17},
    {"Key ring","Library clearance slip","Documents","White","A library clearance slip in a transparent plastic sleeve.",19},
    {"Lunch box","Department approval letter","Documents","Cream","A single-page approval letter inside a cream envelope.",16},
    {"Drawing kit","Engineering drawing portfolio","Documents","Black","A flat black portfolio with folded practice drawings.",14},
    {"Power bank","Portable project drive","Electronics","Silver","A portable drive in a padded case with a geometric key tag.",17},
    {"Sports cap","Sports event permission form","Documents","White","A folded permission form in a reusable zip folder.",20},
    {"Textbook","Scholarship application folder","Documents","Orange","An orange document folder with a fictional application checklist.",18},
    {"Safety glasses","Lab safety training card","Documents","Yellow","A yellow training card in an unmarked badge sleeve.",16},
    {"Charger","Camera memory card case","Electronics","Grey","A grey case containing a memory card used for campus event photos.",15},
    {"Access card","Studio access pass","Accessories","Blue","A blue studio access pass on a plain lanyard.",21},
    {"Wallet","Language club attendance register","Documents","Red","A red register with sample club attendance sheets.",19},
    {"Ruler","Seminar presentation printouts","Documents","Black","A black paper clip holding a set of printed seminar slides.",14}
};
static const char *demo_claim_evidence="The inside cover has a handwritten circuit table and a torn lower corner.";

static void demo_date(char date[11],const DemoItem *item,int found,int pair) {
    snprintf(date,11,"2026-11-%02u",(unsigned)(item->day+(found && pair%3==2 && item->day<21)));
}

static int upgrade_demo_fixtures(void) {
    if (!sql("BEGIN IMMEDIATE")) return 0;
    int ok=1;
    for (size_t i=0;i<sizeof demo_items/sizeof *demo_items && ok;++i) {
        const DemoItem *item=&demo_items[i];
        for (int found=0;found<2 && ok;++found) {
            char date[11];
            demo_date(date,item,found,(int)i);
            sqlite3_stmt *s=query("UPDATE reports SET name=?,category=?,colour=?,event_date=?,details=? "
                "WHERE name=? AND details='Fictional campus demonstration record.' AND type=? AND id=? "
                "AND uid=(SELECT id FROM users WHERE email=?)");
            bind_text(s,1,item->name); bind_text(s,2,item->category); bind_text(s,3,item->colour);
            bind_text(s,4,date); bind_text(s,5,item->description); bind_text(s,6,item->old_name);
            bind_text(s,7,found?"Found":"Lost");
            sqlite3_bind_int(s,8,2*(int)i+found+1);
            bind_text(s,9,found?"finder@campus.test":"student@campus.test");
            ok=run(s);
        }
    }
    if (ok) {
        sqlite3_stmt *s=query("UPDATE claims SET evidence=? WHERE evidence='A silver sticker is under the cap.' "
            "AND uid=(SELECT id FROM users WHERE email='student@campus.test') "
            "AND report IN (SELECT id FROM reports WHERE name='Lab record file' AND type='Found' AND details=?)");
        bind_text(s,1,demo_claim_evidence); bind_text(s,2,demo_items[0].description);
        ok=run(s);
    }
    if (ok && sql("INSERT OR IGNORE INTO demo_seed VALUES(2)") && sql("COMMIT")) return 1;
    sql("ROLLBACK");
    return 0;
}

static int seed(void) {
    sqlite3_stmt *s=query("SELECT coalesce(max(id),0) FROM demo_seed");
    int version=sqlite3_step(s)==SQLITE_ROW?sqlite3_column_int(s,0):-1;
    sqlite3_finalize(s);
    if (version<0) return 0;
    if (version>=2) return 1;
    if (version==1) return upgrade_demo_fixtures();

    if (!sql("BEGIN IMMEDIATE")) return 0;
    int ok=create_user("student@campus.test","CampusStudent2026",0)
        && create_user("finder@campus.test","CampusFinder2026",0)
        && create_user("admin@campus.test","CampusAdmin2026",1);
    for (size_t i=0;i<sizeof demo_items/sizeof *demo_items && ok;++i) {
        const DemoItem *item=&demo_items[i];
        for (int found=0;found<2 && ok;++found) {
            char date[11];
            demo_date(date,item,found,(int)i);
            s=query("INSERT INTO reports(uid,type,name,category,colour,place,event_date,details,status) "
                "VALUES((SELECT id FROM users WHERE email=?),?,?,?,?,?,?,?,?)");
            bind_text(s,1,found?"finder@campus.test":"student@campus.test");
            bind_text(s,2,found?"Found":"Lost"); bind_text(s,3,item->name);
            bind_text(s,4,item->category); bind_text(s,5,item->colour);
            sqlite3_bind_int(s,6,1+(int)(i%7)); bind_text(s,7,date);
            bind_text(s,8,item->description);
            bind_text(s,9,i==7 || i==19?"Recovered":"Open");
            ok=run(s);
        }
    }
    if (ok) {
        s=query("INSERT INTO claims(report,uid,evidence) SELECT r.id,u.id,? FROM reports r CROSS JOIN users u "
            "WHERE r.name='Lab record file' AND r.type='Found' "
            "AND r.uid=(SELECT id FROM users WHERE email='finder@campus.test') AND u.email='student@campus.test'");
        bind_text(s,1,demo_claim_evidence);
        ok=run(s);
    }
    if (ok && sql("INSERT INTO demo_seed VALUES(2)") && sql("COMMIT")) return 1;
    sql("ROLLBACK");
    return 0;
}

int main(int argc,char **argv) {
    int port=8080;
    for (int i=1;i<argc;++i) {
        if (!strcmp(argv[i],"--demo")) seed_mode=1;
        else if (!strcmp(argv[i],"--port") && i+1<argc) {
            char *end;
            long n=strtol(argv[++i],&end,10);
            if (*end || n<1 || n>65535) { fputs("Invalid port.\n",stderr); return 1; }
            port=(int)n;
        } else { fputs("Usage: campusfind [--demo] [--port NUMBER]\n",stderr); return 1; }
    }
    char schema[16384];
    FILE *f=fopen("schema.sql","rb");
    if (!f) { fputs("Run CampusFind from the extracted project folder.\n",stderr); return 1; }
    size_t n=fread(schema,1,sizeof schema-1,f);
    int read_ok=feof(f) && !ferror(f);
    fclose(f);
    schema[n]=0;
    if (!read_ok || sqlite3_open(seed_mode?"campusfind_demo.db":"campusfind.db",&db)!=SQLITE_OK ||
        !sql(schema) || !sql("CREATE TABLE IF NOT EXISTS demo_seed(id INTEGER PRIMARY KEY)") ||
        !sql("DELETE FROM sessions WHERE expires<=unixepoch()") || (seed_mode && !seed())) {
        fputs("Database setup failed. Check folder write access and SQLite version.\n",stderr);
        if (db) sqlite3_close(db);
        return 1;
    }
#ifdef _WIN32
    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2,2),&winsock)!=0) { sqlite3_close(db); return 1; }
#else
    signal(SIGPIPE,SIG_IGN);
#endif
    Socket server=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET; addr.sin_port=htons((unsigned short)port); addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
#ifdef _WIN32
    BOOL exclusive=TRUE;
    if (server!=BAD_SOCKET) setsockopt(server,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,(const char *)&exclusive,sizeof exclusive);
#else
    int reuse=1;
    if (server!=BAD_SOCKET) setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof reuse);
#endif
    if (server==BAD_SOCKET || bind(server,(const struct sockaddr *)&addr,sizeof addr)!=0 || listen(server,16)!=0) {
        fprintf(stderr,"Could not listen on port %d. Try --port 8081.\n",port);
        if (server!=BAD_SOCKET) close_socket(server);
        sqlite3_close(db);
        return 1;
    }
    printf("CampusFind running at http://127.0.0.1:%d/\n",port);
    fflush(stdout);
    for (;;) {
        Socket client=accept(server,NULL,NULL);
        if (client==BAD_SOCKET) break;
#ifdef _WIN32
        DWORD timeout=3000;
#else
        struct timeval timeout={3,0};
#endif
        setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof timeout);
        setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,(const char *)&timeout,sizeof timeout);
        serve(client,port);
        close_socket(client);
    }
    close_socket(server);
    sqlite3_close(db);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
