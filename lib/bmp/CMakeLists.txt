target_public_headers(parsebgp
    parsebgp_bmp.h
    parsebgp_bmp_opts.h
)

target_sources(parsebgp PRIVATE
    parsebgp_bmp.c
    parsebgp_bmp.h
    parsebgp_bmp_opts.c
    parsebgp_bmp_opts.h
)
