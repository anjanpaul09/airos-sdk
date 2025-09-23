#ifndef ISO3166_H_INCLUDED
#define ISO3166_H_INCLUDED

struct iso3166_entry {
    char *name;
    char *alpha2;
    char *alpha3;
    int num;
};

const struct iso3166_entry *
iso3166_lookup_by_alpha2(const char *alpha2);

const struct iso3166_entry *
iso3166_lookup_by_num(const int num);

#endif
