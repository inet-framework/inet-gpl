/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_YY_PARSER_H_INCLUDED
# define YY_YY_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    ELLIPSIS = 258,                /* ELLIPSIS  */
    UDP = 259,                     /* UDP  */
    _HTONS_ = 260,                 /* _HTONS_  */
    _HTONL_ = 261,                 /* _HTONL_  */
    BACK_QUOTED = 262,             /* BACK_QUOTED  */
    SA_FAMILY = 263,               /* SA_FAMILY  */
    SIN_PORT = 264,                /* SIN_PORT  */
    SIN_ADDR = 265,                /* SIN_ADDR  */
    ACK = 266,                     /* ACK  */
    WIN = 267,                     /* WIN  */
    WSCALE = 268,                  /* WSCALE  */
    MSS = 269,                     /* MSS  */
    NOP = 270,                     /* NOP  */
    TIMESTAMP = 271,               /* TIMESTAMP  */
    ECR = 272,                     /* ECR  */
    EOL = 273,                     /* EOL  */
    TCPSACK = 274,                 /* TCPSACK  */
    VAL = 275,                     /* VAL  */
    SACKOK = 276,                  /* SACKOK  */
    URG = 277,                     /* URG  */
    MD5 = 278,                     /* MD5  */
    FO = 279,                      /* FO  */
    FOEXP = 280,                   /* FOEXP  */
    ACCECN = 281,                  /* ACCECN  */
    ACCECN_E0B = 282,              /* ACCECN_E0B  */
    ACCECN_E1B = 283,              /* ACCECN_E1B  */
    ACCECN_CEB = 284,              /* ACCECN_CEB  */
    OPTION = 285,                  /* OPTION  */
    IPV4_TYPE = 286,               /* IPV4_TYPE  */
    IPV6_TYPE = 287,               /* IPV6_TYPE  */
    INET_ADDR = 288,               /* INET_ADDR  */
    SPP_ASSOC_ID = 289,            /* SPP_ASSOC_ID  */
    SPP_ADDRESS = 290,             /* SPP_ADDRESS  */
    SPP_HBINTERVAL = 291,          /* SPP_HBINTERVAL  */
    SPP_PATHMAXRXT = 292,          /* SPP_PATHMAXRXT  */
    SPP_PATHMTU = 293,             /* SPP_PATHMTU  */
    SPP_FLAGS = 294,               /* SPP_FLAGS  */
    SPP_IPV6_FLOWLABEL_ = 295,     /* SPP_IPV6_FLOWLABEL_  */
    SPP_DSCP_ = 296,               /* SPP_DSCP_  */
    SINFO_STREAM = 297,            /* SINFO_STREAM  */
    SINFO_SSN = 298,               /* SINFO_SSN  */
    SINFO_FLAGS = 299,             /* SINFO_FLAGS  */
    SINFO_PPID = 300,              /* SINFO_PPID  */
    SINFO_CONTEXT = 301,           /* SINFO_CONTEXT  */
    SINFO_ASSOC_ID = 302,          /* SINFO_ASSOC_ID  */
    SINFO_TIMETOLIVE = 303,        /* SINFO_TIMETOLIVE  */
    SINFO_TSN = 304,               /* SINFO_TSN  */
    SINFO_CUMTSN = 305,            /* SINFO_CUMTSN  */
    SINFO_PR_VALUE = 306,          /* SINFO_PR_VALUE  */
    CHUNK = 307,                   /* CHUNK  */
    MYDATA = 308,                  /* MYDATA  */
    MYINIT = 309,                  /* MYINIT  */
    MYINIT_ACK = 310,              /* MYINIT_ACK  */
    MYHEARTBEAT = 311,             /* MYHEARTBEAT  */
    MYHEARTBEAT_ACK = 312,         /* MYHEARTBEAT_ACK  */
    MYABORT = 313,                 /* MYABORT  */
    MYSHUTDOWN = 314,              /* MYSHUTDOWN  */
    MYSHUTDOWN_ACK = 315,          /* MYSHUTDOWN_ACK  */
    MYERROR = 316,                 /* MYERROR  */
    MYCOOKIE_ECHO = 317,           /* MYCOOKIE_ECHO  */
    MYCOOKIE_ACK = 318,            /* MYCOOKIE_ACK  */
    MYSHUTDOWN_COMPLETE = 319,     /* MYSHUTDOWN_COMPLETE  */
    PAD = 320,                     /* PAD  */
    ERROR = 321,                   /* ERROR  */
    HEARTBEAT_INFORMATION = 322,   /* HEARTBEAT_INFORMATION  */
    CAUSE_INFO = 323,              /* CAUSE_INFO  */
    MYSACK = 324,                  /* MYSACK  */
    STATE_COOKIE = 325,            /* STATE_COOKIE  */
    PARAMETER = 326,               /* PARAMETER  */
    MYSCTP = 327,                  /* MYSCTP  */
    TYPE = 328,                    /* TYPE  */
    FLAGS = 329,                   /* FLAGS  */
    LEN = 330,                     /* LEN  */
    MYSUPPORTED_EXTENSIONS = 331,  /* MYSUPPORTED_EXTENSIONS  */
    MYSUPPORTED_ADDRESS_TYPES = 332, /* MYSUPPORTED_ADDRESS_TYPES  */
    TYPES = 333,                   /* TYPES  */
    CWR = 334,                     /* CWR  */
    ECNE = 335,                    /* ECNE  */
    TAG = 336,                     /* TAG  */
    A_RWND = 337,                  /* A_RWND  */
    OS = 338,                      /* OS  */
    IS = 339,                      /* IS  */
    TSN = 340,                     /* TSN  */
    MYSID = 341,                   /* MYSID  */
    SSN = 342,                     /* SSN  */
    PPID = 343,                    /* PPID  */
    CUM_TSN = 344,                 /* CUM_TSN  */
    GAPS = 345,                    /* GAPS  */
    DUPS = 346,                    /* DUPS  */
    MID = 347,                     /* MID  */
    FSN = 348,                     /* FSN  */
    SRTO_ASSOC_ID = 349,           /* SRTO_ASSOC_ID  */
    SRTO_INITIAL = 350,            /* SRTO_INITIAL  */
    SRTO_MAX = 351,                /* SRTO_MAX  */
    SRTO_MIN = 352,                /* SRTO_MIN  */
    SINIT_NUM_OSTREAMS = 353,      /* SINIT_NUM_OSTREAMS  */
    SINIT_MAX_INSTREAMS = 354,     /* SINIT_MAX_INSTREAMS  */
    SINIT_MAX_ATTEMPTS = 355,      /* SINIT_MAX_ATTEMPTS  */
    SINIT_MAX_INIT_TIMEO = 356,    /* SINIT_MAX_INIT_TIMEO  */
    MYSACK_DELAY = 357,            /* MYSACK_DELAY  */
    SACK_FREQ = 358,               /* SACK_FREQ  */
    ASSOC_VALUE = 359,             /* ASSOC_VALUE  */
    ASSOC_ID = 360,                /* ASSOC_ID  */
    SACK_ASSOC_ID = 361,           /* SACK_ASSOC_ID  */
    RECONFIG = 362,                /* RECONFIG  */
    OUTGOING_SSN_RESET = 363,      /* OUTGOING_SSN_RESET  */
    REQ_SN = 364,                  /* REQ_SN  */
    RESP_SN = 365,                 /* RESP_SN  */
    LAST_TSN = 366,                /* LAST_TSN  */
    SIDS = 367,                    /* SIDS  */
    INCOMING_SSN_RESET = 368,      /* INCOMING_SSN_RESET  */
    RECONFIG_RESPONSE = 369,       /* RECONFIG_RESPONSE  */
    RESULT = 370,                  /* RESULT  */
    SENDER_NEXT_TSN = 371,         /* SENDER_NEXT_TSN  */
    RECEIVER_NEXT_TSN = 372,       /* RECEIVER_NEXT_TSN  */
    SSN_TSN_RESET = 373,           /* SSN_TSN_RESET  */
    ADD_INCOMING_STREAMS = 374,    /* ADD_INCOMING_STREAMS  */
    NUMBER_OF_NEW_STREAMS = 375,   /* NUMBER_OF_NEW_STREAMS  */
    ADD_OUTGOING_STREAMS = 376,    /* ADD_OUTGOING_STREAMS  */
    RECONFIG_REQUEST_GENERIC = 377, /* RECONFIG_REQUEST_GENERIC  */
    SRS_ASSOC_ID = 378,            /* SRS_ASSOC_ID  */
    SRS_FLAGS = 379,               /* SRS_FLAGS  */
    SRS_NUMBER_STREAMS = 380,      /* SRS_NUMBER_STREAMS  */
    SRS_STREAM_LIST = 381,         /* SRS_STREAM_LIST  */
    SSTAT_ASSOC_ID = 382,          /* SSTAT_ASSOC_ID  */
    SSTAT_STATE = 383,             /* SSTAT_STATE  */
    SSTAT_RWND = 384,              /* SSTAT_RWND  */
    SSTAT_UNACKDATA = 385,         /* SSTAT_UNACKDATA  */
    SSTAT_PENDDATA = 386,          /* SSTAT_PENDDATA  */
    SSTAT_INSTRMS = 387,           /* SSTAT_INSTRMS  */
    SSTAT_OUTSTRMS = 388,          /* SSTAT_OUTSTRMS  */
    SSTAT_FRAGMENTATION_POINT = 389, /* SSTAT_FRAGMENTATION_POINT  */
    SSTAT_PRIMARY = 390,           /* SSTAT_PRIMARY  */
    SASOC_ASOCMAXRXT = 391,        /* SASOC_ASOCMAXRXT  */
    SASOC_ASSOC_ID = 392,          /* SASOC_ASSOC_ID  */
    SASOC_NUMBER_PEER_DESTINATIONS = 393, /* SASOC_NUMBER_PEER_DESTINATIONS  */
    SASOC_PEER_RWND = 394,         /* SASOC_PEER_RWND  */
    SASOC_LOCAL_RWND = 395,        /* SASOC_LOCAL_RWND  */
    SASOC_COOKIE_LIFE = 396,       /* SASOC_COOKIE_LIFE  */
    SAS_ASSOC_ID = 397,            /* SAS_ASSOC_ID  */
    SAS_INSTRMS = 398,             /* SAS_INSTRMS  */
    SAS_OUTSTRMS = 399,            /* SAS_OUTSTRMS  */
    MYINVALID_STREAM_IDENTIFIER = 400, /* MYINVALID_STREAM_IDENTIFIER  */
    ISID = 401,                    /* ISID  */
    MYFLOAT = 402,                 /* MYFLOAT  */
    INTEGER = 403,                 /* INTEGER  */
    HEX_INTEGER = 404,             /* HEX_INTEGER  */
    MYWORD = 405,                  /* MYWORD  */
    MYSTRING = 406                 /* MYSTRING  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 232 "parser.y"

    int64_t integer;
    double floating;
    char *string;
    char *reserved;
    int64_t time_usecs;
    enum direction_t direction;
    uint16_t port;
    int32_t window;
    uint32_t sequence_number;
    struct {
        int protocol;    /* IPPROTO_TCP or IPPROTO_UDP */
        uint32_t start_sequence;
        uint16_t payload_bytes;
    } tcp_sequence_info;
    PacketDrillEvent *event;
    PacketDrillPacket *packet;
    struct syscall_spec *syscall;
    struct command_spec *command;
    PacketDrillStruct *sack_block;
    PacketDrillStruct *cause_item;
    PacketDrillExpression *expression;
    cQueue *expression_list;
    PacketDrillTcpOption *tcp_option;
    PacketDrillSctpParameter *sctp_parameter;
    PacketDrillOption *option;
    cQueue *tcp_options;
    struct errno_spec *errno_info;
    cQueue *sctp_chunk_list;
    cQueue *sctp_parameter_list;
    cQueue *address_types_list;
    cQueue *sack_block_list;
    cQueue *stream_list;
    cQueue *cause_list;
    PacketDrillBytes *byte_list;
    uint8_t byte;
    PacketDrillSctpChunk *sctp_chunk;

#line 254 "parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif


extern YYSTYPE yylval;
extern YYLTYPE yylloc;

int yyparse (void);


#endif /* !YY_YY_PARSER_H_INCLUDED  */
