#include "dsa.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define BUCKETS 257
typedef struct Entry {
    Report report;
    struct Entry *hash_next, *same_name;
} Entry;

typedef struct Trie Trie;
typedef struct Branch {
    unsigned char key;
    Trie *node;
    struct Branch *next;
} Branch;
struct Trie {
    Branch *children;
    Entry *entries;
};
struct Index {
    Entry *buckets[BUCKETS];
    Trie root;
};

Index *index_new(void) { return calloc(1, sizeof(Index)); }

static Trie *child(Trie *node, unsigned char key, int create) {
    for (Branch *p = node->children; p; p = p->next)
        if (p->key == key) return p->node;
    if (!create) return NULL;
    Branch *branch = malloc(sizeof *branch);
    if (!branch) return NULL;
    branch->node = calloc(1, sizeof *branch->node);
    if (!branch->node) { free(branch); return NULL; }
    branch->key = key;
    branch->next = node->children;
    node->children = branch;
    return branch->node;
}

int index_add(Index *index, const Report *report) {
    Trie *node = &index->root;
    for (const unsigned char *c = (const unsigned char *)report->name; *c; ++c) {
        node = child(node, (unsigned char)tolower(*c), 1);
        if (!node) return 0;
    }
    Entry *entry = malloc(sizeof *entry);
    if (!entry) return 0;
    unsigned slot = (unsigned)report->id % BUCKETS;
    entry->report = *report;
    entry->hash_next = index->buckets[slot];
    entry->same_name = node->entries;
    node->entries = entry;
    index->buckets[slot] = entry;
    return 1;
}

const Report *index_lookup(const Index *index, int id) {
    for (Entry *p = index->buckets[(unsigned)id % BUCKETS]; p; p = p->hash_next)
        if (p->report.id == id) return &p->report;
    return NULL;
}

static void visit(const Trie *node, void (*emit)(const Report *)) {
    for (Entry *p = node->entries; p; p = p->same_name) emit(&p->report);
    for (Branch *p = node->children; p; p = p->next) visit(p->node, emit);
}

void index_prefix(const Index *index, const char *prefix, void (*emit)(const Report *)) {
    Trie *node = (Trie *)&index->root;
    for (const unsigned char *c = (const unsigned char *)prefix; *c && node; ++c)
        node = child(node, (unsigned char)tolower(*c), 0);
    if (node) visit(node, emit);
}

static void free_trie(Trie *node) {
    while (node->children) {
        Branch *branch = node->children;
        node->children = branch->next;
        free_trie(branch->node);
        free(branch->node);
        free(branch);
    }
}

void index_free(Index *index) {
    if (!index) return;
    free_trie(&index->root);
    for (int i = 0; i < BUCKETS; ++i) {
        while (index->buckets[i]) {
            Entry *entry = index->buckets[i];
            index->buckets[i] = entry->hash_next;
            free(entry);
        }
    }
    free(index);
}

static int equal(const char *a, const char *b) {
    while (*a && *b && tolower((unsigned char)*a) == tolower((unsigned char)*b)) {
        ++a;
        ++b;
    }
    return *a == *b;
}

/* Convert a validated ISO date into an ordinal for date-gap scoring. */
static int ordinal(const char *date) {
    int year = atoi(date), month = atoi(date + 5), day = atoi(date + 8);
    static const int offsets[] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int previous = year - 1;
    int leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    return previous * 365 + previous / 4 - previous / 100 + previous / 400
        + offsets[month - 1] + day + (month > 2 && leap);
}

int match_score(const Report *a, const Report *b) {
    int gap = abs(ordinal(a->date) - ordinal(b->date));
    int date_points = gap == 0 ? 15 : gap <= 3 ? 10 : gap <= 7 ? 5 : 0;
    return 25 * equal(a->name,b->name) + 25 * equal(a->category,b->category)
        + 15 * equal(a->colour,b->colour) + 20 * (a->place == b->place) + date_points;
}

static int first(Match a, Match b) {
    return a.score > b.score || (a.score == b.score && a.report->id <= b.report->id);
}

void merge_matches(Match *items, Match *scratch, size_t count) {
    if (count < 2) return;
    size_t mid = count / 2, left = 0, right = mid;
    merge_matches(items, scratch, mid);
    merge_matches(items + mid, scratch + mid, count - mid);
    for (size_t i = 0; i < count; ++i) {
        if (right == count || (left < mid && first(items[left], items[right])))
            scratch[i] = items[left++];
        else scratch[i] = items[right++];
    }
    memcpy(items, scratch, count * sizeof *items);
}

int shortest(int graph[PLACES][PLACES], int start, int end, int path[PLACES], int *distance) {
    int dist[PLACES], parent[PLACES], seen[PLACES] = {0};
    for (int i = 0; i < PLACES; ++i) { dist[i] = INF; parent[i] = -1; }
    dist[start] = 0;
    for (int round = 0; round < PLACES; ++round) {
        int best = -1;
        for (int i = 0; i < PLACES; ++i)
            if (!seen[i] && dist[i] < INF && (best < 0 || dist[i] < dist[best])) best = i;
        if (best < 0 || best == end) break;
        seen[best] = 1;
        for (int i = 0; i < PLACES; ++i) {
            int weight = graph[best][i];
            if (weight > 0 && weight < INF - dist[best] && dist[best] + weight < dist[i]) {
                dist[i] = dist[best] + weight;
                parent[i] = best;
            }
        }
    }
    if (dist[end] == INF) return 0;
    int length = 0;
    for (int i = end; i >= 0; i = parent[i]) path[length++] = i;
    *distance = dist[end];
    for (int i = 0; i < length / 2; ++i) {
        int tmp = path[i];
        path[i] = path[length - 1 - i];
        path[length - 1 - i] = tmp;
    }
    return length;
}
