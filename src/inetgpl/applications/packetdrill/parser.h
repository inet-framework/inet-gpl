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
    OPTION = 303,                  /* OPTION  */
    IPV4_TYPE = 304,               /* IPV4_TYPE  */
    IPV6_TYPE = 305,               /* IPV6_TYPE  */
    INET_ADDR = 306,               /* INET_ADDR  */
    SPP_ASSOC_ID = 307,            /* SPP_ASSOC_ID  */
    SPP_ADDRESS = 308,             /* SPP_ADDRESS  */
    SPP_HBINTERVAL = 309,          /* SPP_HBINTERVAL  */
    SPP_PATHMAXRXT = 310,          /* SPP_PATHMAXRXT  */
    SPP_PATHMTU = 311,             /* SPP_PATHMTU  */
    SPP_FLAGS = 312,               /* SPP_FLAGS  */
    SPP_IPV6_FLOWLABEL_ = 313,     /* SPP_IPV6_FLOWLABEL_  */
    SPP_DSCP_ = 314,               /* SPP_DSCP_  */
    SINFO_STREAM = 315,            /* SINFO_STREAM  */
    SINFO_SSN = 316,               /* SINFO_SSN  */
    SINFO_FLAGS = 317,             /* SINFO_FLAGS  */
    SINFO_PPID = 318,              /* SINFO_PPID  */
    SINFO_CONTEXT = 319,           /* SINFO_CONTEXT  */
    SINFO_ASSOC_ID = 320,          /* SINFO_ASSOC_ID  */
    SINFO_TIMETOLIVE = 321,        /* SINFO_TIMETOLIVE  */
    SINFO_TSN = 322,               /* SINFO_TSN  */
    SINFO_CUMTSN = 323,            /* SINFO_CUMTSN  */
    SINFO_PR_VALUE = 324,          /* SINFO_PR_VALUE  */
    CHUNK = 325,                   /* CHUNK  */
    MYDATA = 326,                  /* MYDATA  */
    MYINIT = 327,                  /* MYINIT  */
    MYINIT_ACK = 328,              /* MYINIT_ACK  */
    MYHEARTBEAT = 329,             /* MYHEARTBEAT  */
    MYHEARTBEAT_ACK = 330,         /* MYHEARTBEAT_ACK  */
    MYABORT = 331,                 /* MYABORT  */
    MYSHUTDOWN = 332,              /* MYSHUTDOWN  */
    MYSHUTDOWN_ACK = 333,          /* MYSHUTDOWN_ACK  */
    MYERROR = 334,                 /* MYERROR  */
    MYCOOKIE_ECHO = 335,           /* MYCOOKIE_ECHO  */
    MYCOOKIE_ACK = 336,            /* MYCOOKIE_ACK  */
    MYSHUTDOWN_COMPLETE = 337,     /* MYSHUTDOWN_COMPLETE  */
    PAD = 338,                     /* PAD  */
    ERROR = 339,                   /* ERROR  */
    HEARTBEAT_INFORMATION = 340,   /* HEARTBEAT_INFORMATION  */
    CAUSE_INFO = 341,              /* CAUSE_INFO  */
    MYSACK = 342,                  /* MYSACK  */
    STATE_COOKIE = 343,            /* STATE_COOKIE  */
    PARAMETER = 344,               /* PARAMETER  */
    MYSCTP = 345,                  /* MYSCTP  */
    TYPE = 346,                    /* TYPE  */
    FLAGS = 347,                   /* FLAGS  */
    LEN = 348,                     /* LEN  */
    MYSUPPORTED_EXTENSIONS = 349,  /* MYSUPPORTED_EXTENSIONS  */
    MYSUPPORTED_ADDRESS_TYPES = 350, /* MYSUPPORTED_ADDRESS_TYPES  */
    TYPES = 351,                   /* TYPES  */
    CWR = 352,                     /* CWR  */
    ECNE = 353,                    /* ECNE  */
    TAG = 354,                     /* TAG  */
    A_RWND = 355,                  /* A_RWND  */
    OS = 356,                      /* OS  */
    IS = 357,                      /* IS  */
    TSN = 358,                     /* TSN  */
    MYSID = 359,                   /* MYSID  */
    SSN = 360,                     /* SSN  */
    PPID = 361,                    /* PPID  */
    CUM_TSN = 362,                 /* CUM_TSN  */
    GAPS = 363,                    /* GAPS  */
    DUPS = 364,                    /* DUPS  */
    MID = 365,                     /* MID  */
    FSN = 366,                     /* FSN  */
    SRTO_ASSOC_ID = 367,           /* SRTO_ASSOC_ID  */
    SRTO_INITIAL = 368,            /* SRTO_INITIAL  */
    SRTO_MAX = 369,                /* SRTO_MAX  */
    SRTO_MIN = 370,                /* SRTO_MIN  */
    SINIT_NUM_OSTREAMS = 371,      /* SINIT_NUM_OSTREAMS  */
    SINIT_MAX_INSTREAMS = 372,     /* SINIT_MAX_INSTREAMS  */
    SINIT_MAX_ATTEMPTS = 373,      /* SINIT_MAX_ATTEMPTS  */
    SINIT_MAX_INIT_TIMEO = 374,    /* SINIT_MAX_INIT_TIMEO  */
    MYSACK_DELAY = 375,            /* MYSACK_DELAY  */
    SACK_FREQ = 376,               /* SACK_FREQ  */
    ASSOC_VALUE = 377,             /* ASSOC_VALUE  */
    ASSOC_ID = 378,                /* ASSOC_ID  */
    SACK_ASSOC_ID = 379,           /* SACK_ASSOC_ID  */
    RECONFIG = 380,                /* RECONFIG  */
    OUTGOING_SSN_RESET = 381,      /* OUTGOING_SSN_RESET  */
    REQ_SN = 382,                  /* REQ_SN  */
    RESP_SN = 383,                 /* RESP_SN  */
    LAST_TSN = 384,                /* LAST_TSN  */
    SIDS = 385,                    /* SIDS  */
    INCOMING_SSN_RESET = 386,      /* INCOMING_SSN_RESET  */
    RECONFIG_RESPONSE = 387,       /* RECONFIG_RESPONSE  */
    RESULT = 388,                  /* RESULT  */
    SENDER_NEXT_TSN = 389,         /* SENDER_NEXT_TSN  */
    RECEIVER_NEXT_TSN = 390,       /* RECEIVER_NEXT_TSN  */
    SSN_TSN_RESET = 391,           /* SSN_TSN_RESET  */
    ADD_INCOMING_STREAMS = 392,    /* ADD_INCOMING_STREAMS  */
    NUMBER_OF_NEW_STREAMS = 393,   /* NUMBER_OF_NEW_STREAMS  */
    ADD_OUTGOING_STREAMS = 394,    /* ADD_OUTGOING_STREAMS  */
    RECONFIG_REQUEST_GENERIC = 395, /* RECONFIG_REQUEST_GENERIC  */
    SRS_ASSOC_ID = 396,            /* SRS_ASSOC_ID  */
    SRS_FLAGS = 397,               /* SRS_FLAGS  */
    SRS_NUMBER_STREAMS = 398,      /* SRS_NUMBER_STREAMS  */
    SRS_STREAM_LIST = 399,         /* SRS_STREAM_LIST  */
    SSTAT_ASSOC_ID = 400,          /* SSTAT_ASSOC_ID  */
    SSTAT_STATE = 401,             /* SSTAT_STATE  */
    SSTAT_RWND = 402,              /* SSTAT_RWND  */
    SSTAT_UNACKDATA = 403,         /* SSTAT_UNACKDATA  */
    SSTAT_PENDDATA = 404,          /* SSTAT_PENDDATA  */
    SSTAT_INSTRMS = 405,           /* SSTAT_INSTRMS  */
    SSTAT_OUTSTRMS = 406,          /* SSTAT_OUTSTRMS  */
    SSTAT_FRAGMENTATION_POINT = 407, /* SSTAT_FRAGMENTATION_POINT  */
    SSTAT_PRIMARY = 408,           /* SSTAT_PRIMARY  */
    SASOC_ASOCMAXRXT = 409,        /* SASOC_ASOCMAXRXT  */
    SASOC_ASSOC_ID = 410,          /* SASOC_ASSOC_ID  */
    SASOC_NUMBER_PEER_DESTINATIONS = 411, /* SASOC_NUMBER_PEER_DESTINATIONS  */
    SASOC_PEER_RWND = 412,         /* SASOC_PEER_RWND  */
    SASOC_LOCAL_RWND = 413,        /* SASOC_LOCAL_RWND  */
    SASOC_COOKIE_LIFE = 414,       /* SASOC_COOKIE_LIFE  */
    SAS_ASSOC_ID = 415,            /* SAS_ASSOC_ID  */
    SAS_INSTRMS = 416,             /* SAS_INSTRMS  */
    SAS_OUTSTRMS = 417,            /* SAS_OUTSTRMS  */
    MYINVALID_STREAM_IDENTIFIER = 418, /* MYINVALID_STREAM_IDENTIFIER  */
    ISID = 419,                    /* ISID  */
    MYFLOAT = 420,                 /* MYFLOAT  */
    INTEGER = 421,                 /* INTEGER  */
    HEX_INTEGER = 422,             /* HEX_INTEGER  */
    MYWORD = 423,                  /* MYWORD  */
    MYSTRING = 424                 /* MYSTRING  */
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

#line 272 "parser.h"

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
