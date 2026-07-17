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
    MSG_NAME = 285,                /* MSG_NAME  */
    MSG_IOV = 286,                 /* MSG_IOV  */
    MSG_FLAGS = 287,               /* MSG_FLAGS  */
    MSG_CONTROL = 288,             /* MSG_CONTROL  */
    CMSG_LEVEL = 289,              /* CMSG_LEVEL  */
    CMSG_TYPE = 290,               /* CMSG_TYPE  */
    CMSG_DATA = 291,               /* CMSG_DATA  */
    EVENTS = 292,                  /* EVENTS  */
    FD = 293,                      /* FD  */
    PTR = 294,                     /* PTR  */
    U32 = 295,                     /* U32  */
    U64 = 296,                     /* U64  */
    EE_ERRNO = 297,                /* EE_ERRNO  */
    EE_ORIGIN = 298,               /* EE_ORIGIN  */
    EE_TYPE = 299,                 /* EE_TYPE  */
    EE_CODE = 300,                 /* EE_CODE  */
    EE_INFO = 301,                 /* EE_INFO  */
    EE_DATA = 302,                 /* EE_DATA  */
    SCM_SEC = 303,                 /* SCM_SEC  */
    SCM_NSEC = 304,                /* SCM_NSEC  */
    REVENTS = 305,                 /* REVENTS  */
    ICMP = 306,                    /* ICMP  */
    MTU = 307,                     /* MTU  */
    OPTION = 308,                  /* OPTION  */
    IPV4_TYPE = 309,               /* IPV4_TYPE  */
    IPV6_TYPE = 310,               /* IPV6_TYPE  */
    INET_ADDR = 311,               /* INET_ADDR  */
    SPP_ASSOC_ID = 312,            /* SPP_ASSOC_ID  */
    SPP_ADDRESS = 313,             /* SPP_ADDRESS  */
    SPP_HBINTERVAL = 314,          /* SPP_HBINTERVAL  */
    SPP_PATHMAXRXT = 315,          /* SPP_PATHMAXRXT  */
    SPP_PATHMTU = 316,             /* SPP_PATHMTU  */
    SPP_FLAGS = 317,               /* SPP_FLAGS  */
    SPP_IPV6_FLOWLABEL_ = 318,     /* SPP_IPV6_FLOWLABEL_  */
    SPP_DSCP_ = 319,               /* SPP_DSCP_  */
    SINFO_STREAM = 320,            /* SINFO_STREAM  */
    SINFO_SSN = 321,               /* SINFO_SSN  */
    SINFO_FLAGS = 322,             /* SINFO_FLAGS  */
    SINFO_PPID = 323,              /* SINFO_PPID  */
    SINFO_CONTEXT = 324,           /* SINFO_CONTEXT  */
    SINFO_ASSOC_ID = 325,          /* SINFO_ASSOC_ID  */
    SINFO_TIMETOLIVE = 326,        /* SINFO_TIMETOLIVE  */
    SINFO_TSN = 327,               /* SINFO_TSN  */
    SINFO_CUMTSN = 328,            /* SINFO_CUMTSN  */
    SINFO_PR_VALUE = 329,          /* SINFO_PR_VALUE  */
    CHUNK = 330,                   /* CHUNK  */
    MYDATA = 331,                  /* MYDATA  */
    MYINIT = 332,                  /* MYINIT  */
    MYINIT_ACK = 333,              /* MYINIT_ACK  */
    MYHEARTBEAT = 334,             /* MYHEARTBEAT  */
    MYHEARTBEAT_ACK = 335,         /* MYHEARTBEAT_ACK  */
    MYABORT = 336,                 /* MYABORT  */
    MYSHUTDOWN = 337,              /* MYSHUTDOWN  */
    MYSHUTDOWN_ACK = 338,          /* MYSHUTDOWN_ACK  */
    MYERROR = 339,                 /* MYERROR  */
    MYCOOKIE_ECHO = 340,           /* MYCOOKIE_ECHO  */
    MYCOOKIE_ACK = 341,            /* MYCOOKIE_ACK  */
    MYSHUTDOWN_COMPLETE = 342,     /* MYSHUTDOWN_COMPLETE  */
    PAD = 343,                     /* PAD  */
    ERROR = 344,                   /* ERROR  */
    HEARTBEAT_INFORMATION = 345,   /* HEARTBEAT_INFORMATION  */
    CAUSE_INFO = 346,              /* CAUSE_INFO  */
    MYSACK = 347,                  /* MYSACK  */
    STATE_COOKIE = 348,            /* STATE_COOKIE  */
    PARAMETER = 349,               /* PARAMETER  */
    MYSCTP = 350,                  /* MYSCTP  */
    TYPE = 351,                    /* TYPE  */
    FLAGS = 352,                   /* FLAGS  */
    LEN = 353,                     /* LEN  */
    MYSUPPORTED_EXTENSIONS = 354,  /* MYSUPPORTED_EXTENSIONS  */
    MYSUPPORTED_ADDRESS_TYPES = 355, /* MYSUPPORTED_ADDRESS_TYPES  */
    TYPES = 356,                   /* TYPES  */
    CWR = 357,                     /* CWR  */
    ECNE = 358,                    /* ECNE  */
    TAG = 359,                     /* TAG  */
    A_RWND = 360,                  /* A_RWND  */
    OS = 361,                      /* OS  */
    IS = 362,                      /* IS  */
    TSN = 363,                     /* TSN  */
    MYSID = 364,                   /* MYSID  */
    SSN = 365,                     /* SSN  */
    PPID = 366,                    /* PPID  */
    CUM_TSN = 367,                 /* CUM_TSN  */
    GAPS = 368,                    /* GAPS  */
    DUPS = 369,                    /* DUPS  */
    MID = 370,                     /* MID  */
    FSN = 371,                     /* FSN  */
    SRTO_ASSOC_ID = 372,           /* SRTO_ASSOC_ID  */
    SRTO_INITIAL = 373,            /* SRTO_INITIAL  */
    SRTO_MAX = 374,                /* SRTO_MAX  */
    SRTO_MIN = 375,                /* SRTO_MIN  */
    SINIT_NUM_OSTREAMS = 376,      /* SINIT_NUM_OSTREAMS  */
    SINIT_MAX_INSTREAMS = 377,     /* SINIT_MAX_INSTREAMS  */
    SINIT_MAX_ATTEMPTS = 378,      /* SINIT_MAX_ATTEMPTS  */
    SINIT_MAX_INIT_TIMEO = 379,    /* SINIT_MAX_INIT_TIMEO  */
    MYSACK_DELAY = 380,            /* MYSACK_DELAY  */
    SACK_FREQ = 381,               /* SACK_FREQ  */
    ASSOC_VALUE = 382,             /* ASSOC_VALUE  */
    ASSOC_ID = 383,                /* ASSOC_ID  */
    SACK_ASSOC_ID = 384,           /* SACK_ASSOC_ID  */
    RECONFIG = 385,                /* RECONFIG  */
    OUTGOING_SSN_RESET = 386,      /* OUTGOING_SSN_RESET  */
    REQ_SN = 387,                  /* REQ_SN  */
    RESP_SN = 388,                 /* RESP_SN  */
    LAST_TSN = 389,                /* LAST_TSN  */
    SIDS = 390,                    /* SIDS  */
    INCOMING_SSN_RESET = 391,      /* INCOMING_SSN_RESET  */
    RECONFIG_RESPONSE = 392,       /* RECONFIG_RESPONSE  */
    RESULT = 393,                  /* RESULT  */
    SENDER_NEXT_TSN = 394,         /* SENDER_NEXT_TSN  */
    RECEIVER_NEXT_TSN = 395,       /* RECEIVER_NEXT_TSN  */
    SSN_TSN_RESET = 396,           /* SSN_TSN_RESET  */
    ADD_INCOMING_STREAMS = 397,    /* ADD_INCOMING_STREAMS  */
    NUMBER_OF_NEW_STREAMS = 398,   /* NUMBER_OF_NEW_STREAMS  */
    ADD_OUTGOING_STREAMS = 399,    /* ADD_OUTGOING_STREAMS  */
    RECONFIG_REQUEST_GENERIC = 400, /* RECONFIG_REQUEST_GENERIC  */
    SRS_ASSOC_ID = 401,            /* SRS_ASSOC_ID  */
    SRS_FLAGS = 402,               /* SRS_FLAGS  */
    SRS_NUMBER_STREAMS = 403,      /* SRS_NUMBER_STREAMS  */
    SRS_STREAM_LIST = 404,         /* SRS_STREAM_LIST  */
    SSTAT_ASSOC_ID = 405,          /* SSTAT_ASSOC_ID  */
    SSTAT_STATE = 406,             /* SSTAT_STATE  */
    SSTAT_RWND = 407,              /* SSTAT_RWND  */
    SSTAT_UNACKDATA = 408,         /* SSTAT_UNACKDATA  */
    SSTAT_PENDDATA = 409,          /* SSTAT_PENDDATA  */
    SSTAT_INSTRMS = 410,           /* SSTAT_INSTRMS  */
    SSTAT_OUTSTRMS = 411,          /* SSTAT_OUTSTRMS  */
    SSTAT_FRAGMENTATION_POINT = 412, /* SSTAT_FRAGMENTATION_POINT  */
    SSTAT_PRIMARY = 413,           /* SSTAT_PRIMARY  */
    SASOC_ASOCMAXRXT = 414,        /* SASOC_ASOCMAXRXT  */
    SASOC_ASSOC_ID = 415,          /* SASOC_ASSOC_ID  */
    SASOC_NUMBER_PEER_DESTINATIONS = 416, /* SASOC_NUMBER_PEER_DESTINATIONS  */
    SASOC_PEER_RWND = 417,         /* SASOC_PEER_RWND  */
    SASOC_LOCAL_RWND = 418,        /* SASOC_LOCAL_RWND  */
    SASOC_COOKIE_LIFE = 419,       /* SASOC_COOKIE_LIFE  */
    SAS_ASSOC_ID = 420,            /* SAS_ASSOC_ID  */
    SAS_INSTRMS = 421,             /* SAS_INSTRMS  */
    SAS_OUTSTRMS = 422,            /* SAS_OUTSTRMS  */
    MYINVALID_STREAM_IDENTIFIER = 423, /* MYINVALID_STREAM_IDENTIFIER  */
    ISID = 424,                    /* ISID  */
    MYFLOAT = 425,                 /* MYFLOAT  */
    INTEGER = 426,                 /* INTEGER  */
    HEX_INTEGER = 427,             /* HEX_INTEGER  */
    MYWORD = 428,                  /* MYWORD  */
    MYSTRING = 429,                /* MYSTRING  */
    CODE = 430                     /* CODE  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 294 "parser.y"

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
    struct code_spec *code;
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

#line 279 "parser.h"

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
