#include <stddef.h>
#define PLACES 32
#define INF 1000000000
typedef struct {
    int id, place;
    char type[8], name[81], category[41], colour[41], date[11];
} Report;
typedef struct {
    const Report *report;
    int score;
} Match;
typedef struct Index Index;
Index *index_new(void);
int index_add(Index *, const Report *);
const Report *index_lookup(const Index *, int);
void index_prefix(const Index *, const char *, void (*)(const Report *));
void index_free(Index *);
int match_score(const Report *, const Report *);
void merge_matches(Match *, Match *, size_t);
int shortest(int graph[PLACES][PLACES], int start, int end, int path[PLACES], int *distance);
