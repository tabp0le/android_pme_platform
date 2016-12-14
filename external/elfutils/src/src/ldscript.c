
/* Bison implementation for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */


#define YYBISON 1

#define YYBISON_VERSION "2.7"

#define YYSKELETON_NAME "yacc.c"

#define YYPURE 0

#define YYPUSH 0

#define YYPULL 1


#define yyparse         ldparse
#define yylex           ldlex
#define yyerror         lderror
#define yylval          ldlval
#define yychar          ldchar
#define yydebug         lddebug
#define yynerrs         ldnerrs

#line 1 "/home/mark/src/elfutils/src/ldscript.y"

/* Parser for linker scripts.
   Copyright (C) 2001-2011 Red Hat, Inc.
   This file is part of elfutils.
   Written by Ulrich Drepper <drepper@redhat.com>, 2001.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <error.h>
#include <libintl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <system.h>
#include <ld.h>

static void yyerror (const char *s);

static struct expression *new_expr (int tag);
static struct input_section_name *new_input_section_name (const char *name,
							  bool sort_flag);
static struct input_rule *new_input_rule (int tag);
static struct output_rule *new_output_rule (int tag);
static struct assignment *new_assignment (const char *variable,
					  struct expression *expression,
					  bool provide_flag);
static void new_segment (int mode, struct output_rule *output_rule);
static struct filename_list *new_filename_listelem (const char *string);
static void add_inputfiles (struct filename_list *fnames);
static struct id_list *new_id_listelem (const char *str);
 static struct filename_list *mark_as_needed (struct filename_list *listp);
static struct version *new_version (struct id_list *local,
				    struct id_list *global);
static struct version *merge_versions (struct version *one,
				       struct version *two);
static void add_versions (struct version *versions);

extern int yylex (void);

#line 137 "ldscript.c"

# ifndef YY_NULL
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULL nullptr
#  else
#   define YY_NULL 0
#  endif
# endif

#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#ifndef YY_LD_LDSCRIPT_H_INCLUDED
# define YY_LD_LDSCRIPT_H_INCLUDED
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int lddebug;
#endif

#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   enum yytokentype {
     kADD_OP = 258,
     kALIGN = 259,
     kAS_NEEDED = 260,
     kENTRY = 261,
     kEXCLUDE_FILE = 262,
     kFILENAME = 263,
     kGLOBAL = 264,
     kGROUP = 265,
     kID = 266,
     kINPUT = 267,
     kINTERP = 268,
     kKEEP = 269,
     kLOCAL = 270,
     kMODE = 271,
     kMUL_OP = 272,
     kNUM = 273,
     kOUTPUT_FORMAT = 274,
     kPAGESIZE = 275,
     kPROVIDE = 276,
     kSEARCH_DIR = 277,
     kSEGMENT = 278,
     kSIZEOF_HEADERS = 279,
     kSORT = 280,
     kVERSION = 281,
     kVERSION_SCRIPT = 282,
     ADD_OP = 283,
     MUL_OP = 284
   };
#endif
#define kADD_OP 258
#define kALIGN 259
#define kAS_NEEDED 260
#define kENTRY 261
#define kEXCLUDE_FILE 262
#define kFILENAME 263
#define kGLOBAL 264
#define kGROUP 265
#define kID 266
#define kINPUT 267
#define kINTERP 268
#define kKEEP 269
#define kLOCAL 270
#define kMODE 271
#define kMUL_OP 272
#define kNUM 273
#define kOUTPUT_FORMAT 274
#define kPAGESIZE 275
#define kPROVIDE 276
#define kSEARCH_DIR 277
#define kSEGMENT 278
#define kSIZEOF_HEADERS 279
#define kSORT 280
#define kVERSION 281
#define kVERSION_SCRIPT 282
#define ADD_OP 283
#define MUL_OP 284



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
#line 63 "/home/mark/src/elfutils/src/ldscript.y"

  uintmax_t num;
  enum expression_tag op;
  char *str;
  struct expression *expr;
  struct input_section_name *sectionname;
  struct filemask_section_name *filemask_section_name;
  struct input_rule *input_rule;
  struct output_rule *output_rule;
  struct assignment *assignment;
  struct filename_list *filename_list;
  struct version *version;
  struct id_list *id_list;


#line 254 "ldscript.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE 
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE ldlval;

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int ldparse (void *YYPARSE_PARAM);
#else
int ldparse ();
#endif
#else 
#if defined __STDC__ || defined __cplusplus
int ldparse (void);
#else
int ldparse ();
#endif
#endif 

#endif 


#line 282 "ldscript.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> 
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> 
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) 
#endif

#ifndef lint
# define YYID(N) (N)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE


# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> 
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> 
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> 
      
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   
#  define YYSTACK_FREE(Ptr) do { ; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM 4032 
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> 
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); 
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); 
#   endif
#  endif
# endif
#endif 


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (YYID (0))
#  endif
# endif
#endif 

#define YYFINAL  32
#define YYLAST   226

#define YYNTOKENS  40
#define YYNNTS  23
#define YYNRULES  66
#define YYNSTATES  159

#define YYUNDEFTOK  2
#define YYMAXUTOK   284

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    29,     2,
      33,    34,    31,     2,    39,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    35,
       2,    38,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    36,    28,    37,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    30,    32
};

#if YYDEBUG
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     5,     8,    11,    13,    19,    25,    31,
      37,    43,    49,    54,    59,    64,    69,    74,    77,    79,
      82,    87,    90,    94,   101,   104,   106,   108,   113,   116,
     122,   124,   129,   134,   135,   140,   144,   148,   152,   156,
     160,   164,   166,   168,   170,   172,   176,   178,   180,   181,
     186,   191,   193,   196,   198,   203,   209,   216,   219,   221,
     224,   227,   231,   234,   236,   238,   240
};

static const yytype_int8 yyrhs[] =
{
      41,     0,    -1,    42,    -1,    27,    56,    -1,    42,    43,
      -1,    43,    -1,     6,    33,    11,    34,    35,    -1,    22,
      33,    61,    34,    35,    -1,    20,    33,    18,    34,    35,
      -1,    13,    33,    61,    34,    35,    -1,    23,    16,    36,
      44,    37,    -1,    23,     1,    36,    44,    37,    -1,    10,
      33,    53,    34,    -1,    12,    33,    53,    34,    -1,     5,
      33,    53,    34,    -1,    26,    36,    56,    37,    -1,    19,
      33,    61,    34,    -1,    44,    45,    -1,    45,    -1,    46,
      35,    -1,    11,    36,    47,    37,    -1,    11,    35,    -1,
      11,    38,    52,    -1,    21,    33,    11,    38,    52,    34,
      -1,    47,    48,    -1,    48,    -1,    49,    -1,    14,    33,
      49,    34,    -1,    46,    35,    -1,    62,    33,    51,    50,
      34,    -1,    11,    -1,    25,    33,    11,    34,    -1,     7,
      33,    61,    34,    -1,    -1,     4,    33,    52,    34,    -1,
      33,    52,    34,    -1,    52,    31,    52,    -1,    52,    17,
      52,    -1,    52,     3,    52,    -1,    52,    29,    52,    -1,
      52,    28,    52,    -1,    18,    -1,    11,    -1,    24,    -1,
      20,    -1,    53,    54,    55,    -1,    55,    -1,    39,    -1,
      -1,    10,    33,    53,    34,    -1,     5,    33,    53,    34,
      -1,    61,    -1,    56,    57,    -1,    57,    -1,    36,    58,
      37,    35,    -1,    61,    36,    58,    37,    35,    -1,    61,
      36,    58,    37,    61,    35,    -1,    58,    59,    -1,    59,
      -1,     9,    60,    -1,    15,    60,    -1,    60,    62,    35,
      -1,    62,    35,    -1,     8,    -1,    11,    -1,    61,    -1,
      31,    -1
};

static const yytype_uint16 yyrline[] =
{
       0,   135,   135,   136,   140,   141,   144,   149,   153,   158,
     164,   168,   174,   185,   187,   189,   191,   195,   200,   204,
     209,   221,   245,   247,   251,   256,   260,   265,   272,   279,
     290,   292,   296,   299,   302,   307,   309,   315,   321,   327,
     333,   339,   344,   349,   351,   355,   360,   364,   365,   368,
     379,   381,   386,   391,   395,   401,   407,   416,   418,   422,
     424,   429,   435,   439,   441,   445,   447
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "kADD_OP", "kALIGN", "kAS_NEEDED",
  "kENTRY", "kEXCLUDE_FILE", "kFILENAME", "kGLOBAL", "kGROUP", "kID",
  "kINPUT", "kINTERP", "kKEEP", "kLOCAL", "kMODE", "kMUL_OP", "kNUM",
  "kOUTPUT_FORMAT", "kPAGESIZE", "kPROVIDE", "kSEARCH_DIR", "kSEGMENT",
  "kSIZEOF_HEADERS", "kSORT", "kVERSION", "kVERSION_SCRIPT", "'|'", "'&'",
  "ADD_OP", "'*'", "MUL_OP", "'('", "')'", "';'", "'{'", "'}'", "'='",
  "','", "$accept", "script_or_version", "file", "content",
  "outputsections", "outputsection", "assignment", "inputsections",
  "inputsection", "sectionname", "sort_opt_name", "exclude_opt", "expr",
  "filename_id_list", "comma_opt", "filename_id_listelem", "versionlist",
  "version", "version_stmt_list", "version_stmt", "filename_id_star_list",
  "filename_id", "filename_id_star", YY_NULL
};
#endif

# ifdef YYPRINT
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   124,    38,
     283,    42,   284,    40,    41,    59,   123,   125,    61,    44
};
# endif

static const yytype_uint8 yyr1[] =
{
       0,    40,    41,    41,    42,    42,    43,    43,    43,    43,
      43,    43,    43,    43,    43,    43,    43,    44,    44,    45,
      45,    45,    46,    46,    47,    47,    48,    48,    48,    49,
      50,    50,    51,    51,    52,    52,    52,    52,    52,    52,
      52,    52,    52,    52,    52,    53,    53,    54,    54,    55,
      55,    55,    56,    56,    57,    57,    57,    58,    58,    59,
      59,    60,    60,    61,    61,    62,    62
};

static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     2,     2,     1,     5,     5,     5,     5,
       5,     5,     4,     4,     4,     4,     4,     2,     1,     2,
       4,     2,     3,     6,     2,     1,     1,     4,     2,     5,
       1,     4,     4,     0,     4,     3,     3,     3,     3,     3,
       3,     1,     1,     1,     1,     3,     1,     1,     0,     4,
       4,     1,     2,     1,     4,     5,     6,     2,     1,     2,
       2,     3,     2,     1,     1,     1,     1
};

static const yytype_uint8 yydefact[] =
{
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     2,     5,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    63,    64,     0,     3,
      53,     0,     1,     4,     0,     0,    48,    46,    51,     0,
      48,    48,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    58,    52,     0,     0,     0,    14,    47,     0,
       0,    12,    13,     0,    16,     0,     0,     0,     0,     0,
      18,     0,     0,    15,    66,    59,    65,     0,    60,     0,
      57,     0,    48,    48,    45,     6,     9,     8,     7,    21,
       0,     0,     0,    11,    17,    19,    10,     0,    62,    54,
       0,    50,    49,    64,     0,     0,     0,    25,    26,     0,
       0,    42,    41,    44,    43,     0,    22,     0,    61,    55,
       0,     0,    28,    20,    24,    33,     0,     0,     0,     0,
       0,     0,     0,     0,    56,     0,     0,     0,     0,    35,
      38,    37,    40,    39,    36,     0,    27,     0,    30,     0,
       0,    34,    23,     0,     0,    29,    32,     0,    31
};

static const yytype_int16 yydefgoto[] =
{
      -1,    12,    13,    14,    69,    70,    71,   106,   107,   108,
     150,   137,   116,    36,    59,    37,    29,    30,    51,    52,
      75,    76,   109
};

#define YYPACT_NINF -86
static const yytype_int16 yypact[] =
{
     111,   -18,   -14,    23,    45,    70,    75,    85,    92,    97,
      91,    19,   128,   134,   -86,   162,    96,   162,   162,     5,
       5,   123,     5,    93,    99,    19,   -86,   -86,   117,    19,
     -86,   115,   -86,   -86,   125,   144,    71,   -86,   -86,   145,
     116,   135,   147,   148,   149,   150,   101,   101,    14,    83,
      83,    55,   -86,   -86,   117,   162,   162,   -86,   -86,   162,
     133,   -86,   -86,   143,   -86,   151,   152,   107,   155,    63,
     -86,   154,    74,   -86,   -86,    83,   -86,   156,    83,   157,
     -86,    56,   137,   141,   -86,   -86,   -86,   -86,   -86,   -86,
      88,    48,   174,   -86,   -86,   -86,   -86,   158,   -86,   -86,
      69,   -86,   -86,   159,   161,   160,    12,   -86,   -86,   163,
     165,   -86,   -86,   -86,   -86,    48,    59,   164,   -86,   -86,
     166,    83,   -86,   -86,   -86,   183,    48,     0,    48,    48,
      48,    48,    48,    48,   -86,   169,   167,    90,     7,   -86,
      59,    59,    44,    66,   103,    29,   -86,     5,   -86,   171,
     172,   -86,   -86,   173,   188,   -86,   -86,   175,   -86
};

static const yytype_int16 yypgoto[] =
{
     -86,   -86,   -86,   192,   168,    80,   -85,   -86,   102,    89,
     -86,   -86,    33,   -16,   -86,   153,   186,    38,   170,   -39,
     176,   -11,     4
};

#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      31,    40,    41,   128,    38,   105,    38,    38,    42,    43,
     128,    45,    80,    26,    31,    15,    27,   129,    31,    16,
      26,   105,    26,   103,   129,    27,   104,    26,   130,   131,
      27,   132,   128,    68,   139,   130,   131,    31,   132,    82,
      83,   151,    80,    74,    38,    38,   129,   128,    38,   123,
      28,    73,   110,    77,    77,    28,    17,   130,   131,   111,
     132,   129,   128,   152,    49,    49,   112,    53,   113,   128,
      50,    50,   114,   131,    67,   132,   129,    26,    18,    97,
      27,   115,    97,   129,    68,    67,    53,   130,   131,   120,
     132,    26,    79,   100,    27,    68,    26,   132,    23,   103,
      93,   148,   104,    19,   119,    57,   128,    39,    20,    68,
      58,    96,    67,    24,    74,   149,     1,     2,    21,    74,
     129,     3,    68,     4,     5,    22,    49,    25,    32,    46,
       6,     7,    50,     8,     9,    47,   153,    10,    11,     1,
       2,    44,    89,    90,     3,    91,     4,     5,   127,    94,
      61,    54,    94,     6,     7,    58,     8,     9,    55,   138,
      10,   140,   141,   142,   143,   144,   145,    34,    85,    62,
      26,   101,    35,    27,    58,   102,    58,    56,    86,    60,
      58,    63,    64,    65,    66,   117,    87,    88,    92,    95,
     136,    98,    99,   118,   121,   122,   125,    91,   126,   157,
     147,   134,   133,   146,   154,    33,   155,   156,   124,   158,
     135,    48,    84,     0,     0,    72,     0,     0,     0,     0,
       0,     0,     0,     0,    81,     0,    78
};

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-86)))

#define yytable_value_is_error(Yytable_value) \
  YYID (0)

static const yytype_int16 yycheck[] =
{
      11,    17,    18,     3,    15,    90,    17,    18,    19,    20,
       3,    22,    51,     8,    25,    33,    11,    17,    29,    33,
       8,   106,     8,    11,    17,    11,    14,     8,    28,    29,
      11,    31,     3,    21,    34,    28,    29,    48,    31,    55,
      56,    34,    81,    31,    55,    56,    17,     3,    59,    37,
      36,    37,     4,    49,    50,    36,    33,    28,    29,    11,
      31,    17,     3,    34,     9,     9,    18,    29,    20,     3,
      15,    15,    24,    29,    11,    31,    17,     8,    33,    75,
      11,    33,    78,    17,    21,    11,    48,    28,    29,   100,
      31,     8,    37,    37,    11,    21,     8,    31,     1,    11,
      37,    11,    14,    33,    35,    34,     3,    11,    33,    21,
      39,    37,    11,    16,    31,    25,     5,     6,    33,    31,
      17,    10,    21,    12,    13,    33,     9,    36,     0,    36,
      19,    20,    15,    22,    23,    36,   147,    26,    27,     5,
       6,    18,    35,    36,    10,    38,    12,    13,   115,    69,
      34,    36,    72,    19,    20,    39,    22,    23,    33,   126,
      26,   128,   129,   130,   131,   132,   133,     5,    35,    34,
       8,    34,    10,    11,    39,    34,    39,    33,    35,    34,
      39,    34,    34,    34,    34,    11,    35,    35,    33,    35,
       7,    35,    35,    35,    33,    35,    33,    38,    33,    11,
      33,    35,    38,    34,    33,    13,    34,    34,   106,    34,
     121,    25,    59,    -1,    -1,    47,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    54,    -1,    50
};

static const yytype_uint8 yystos[] =
{
       0,     5,     6,    10,    12,    13,    19,    20,    22,    23,
      26,    27,    41,    42,    43,    33,    33,    33,    33,    33,
      33,    33,    33,     1,    16,    36,     8,    11,    36,    56,
      57,    61,     0,    43,     5,    10,    53,    55,    61,    11,
      53,    53,    61,    61,    18,    61,    36,    36,    56,     9,
      15,    58,    59,    57,    36,    33,    33,    34,    39,    54,
      34,    34,    34,    34,    34,    34,    34,    11,    21,    44,
      45,    46,    44,    37,    31,    60,    61,    62,    60,    37,
      59,    58,    53,    53,    55,    35,    35,    35,    35,    35,
      36,    38,    33,    37,    45,    35,    37,    62,    35,    35,
      37,    34,    34,    11,    14,    46,    47,    48,    49,    62,
       4,    11,    18,    20,    24,    33,    52,    11,    35,    35,
      61,    33,    35,    37,    48,    33,    33,    52,     3,    17,
      28,    29,    31,    38,    35,    49,     7,    51,    52,    34,
      52,    52,    52,    52,    52,    52,    34,    33,    11,    25,
      50,    34,    34,    61,    33,    34,    34,    11,    34
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab



#define YYFAIL		goto yyerrlab
#if defined YYFAIL
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))

#define YYTERROR	1
#define YYERRCODE	256


#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> 
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))



#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
        break;
    }
}



#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}


#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))



#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

int yydebug;
#else 
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif 


#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif


#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULL, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  
  const char *yyformat = YY_NULL;
  
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  int yycount = 0;

  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          int yyxbegin = yyn < 0 ? -yyn : 0;
          
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULL, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif 


#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
        break;
    }
}




int yychar;


#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) 
#endif

YYSTYPE yylval YY_INITIAL_VALUE(yyval_default);

int yynerrs;



#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else 
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
    int yystate;
    
    int yyerrstatus;


    
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  
  int yytoken = 0;
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; 
  goto yysetstate;

 yynewstate:
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else 
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif 

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

yybackup:


  
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  

  
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyerrstatus)
    yyerrstatus--;

  
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


yyreduce:
  
  yylen = yyr2[yyn];

  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 3:
#line 137 "/home/mark/src/elfutils/src/ldscript.y"
    { add_versions ((yyvsp[(2) - (2)].version)); }
    break;

  case 6:
#line 145 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      if (likely (ld_state.entry == NULL))
			ld_state.entry = (yyvsp[(3) - (5)].str);
		    }
    break;

  case 7:
#line 150 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      ld_new_searchdir ((yyvsp[(3) - (5)].str));
		    }
    break;

  case 8:
#line 154 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      if (likely (ld_state.pagesize == 0))
			ld_state.pagesize = (yyvsp[(3) - (5)].num);
		    }
    break;

  case 9:
#line 159 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      if (likely (ld_state.interp == NULL)
			  && ld_state.file_type != dso_file_type)
			ld_state.interp = (yyvsp[(3) - (5)].str);
		    }
    break;

  case 10:
#line 165 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      new_segment ((yyvsp[(2) - (5)].num), (yyvsp[(4) - (5)].output_rule));
		    }
    break;

  case 11:
#line 169 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      fputs_unlocked (gettext ("mode for segment invalid\n"),
				      stderr);
		      new_segment (0, (yyvsp[(4) - (5)].output_rule));
		    }
    break;

  case 12:
#line 175 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      if ((yyvsp[(3) - (4)].filename_list) != (yyvsp[(3) - (4)].filename_list)->next)
			{
			  (yyvsp[(3) - (4)].filename_list)->next->group_start = 1;
			  (yyvsp[(3) - (4)].filename_list)->group_end = 1;
			}
		      add_inputfiles ((yyvsp[(3) - (4)].filename_list));
		    }
    break;

  case 13:
#line 186 "/home/mark/src/elfutils/src/ldscript.y"
    { add_inputfiles ((yyvsp[(3) - (4)].filename_list)); }
    break;

  case 14:
#line 188 "/home/mark/src/elfutils/src/ldscript.y"
    { add_inputfiles (mark_as_needed ((yyvsp[(3) - (4)].filename_list))); }
    break;

  case 15:
#line 190 "/home/mark/src/elfutils/src/ldscript.y"
    { add_versions ((yyvsp[(3) - (4)].version)); }
    break;

  case 16:
#line 192 "/home/mark/src/elfutils/src/ldscript.y"
    {  }
    break;

  case 17:
#line 196 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(2) - (2)].output_rule)->next = (yyvsp[(1) - (2)].output_rule)->next;
		      (yyval.output_rule) = (yyvsp[(1) - (2)].output_rule)->next = (yyvsp[(2) - (2)].output_rule);
		    }
    break;

  case 18:
#line 201 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.output_rule) = (yyvsp[(1) - (1)].output_rule); }
    break;

  case 19:
#line 205 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.output_rule) = new_output_rule (output_assignment);
		      (yyval.output_rule)->val.assignment = (yyvsp[(1) - (2)].assignment);
		    }
    break;

  case 20:
#line 210 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.output_rule) = new_output_rule (output_section);
		      (yyval.output_rule)->val.section.name = (yyvsp[(1) - (4)].str);
		      (yyval.output_rule)->val.section.input = (yyvsp[(3) - (4)].input_rule)->next;
		      if (ld_state.strip == strip_debug
			  && ebl_debugscn_p (ld_state.ebl, (yyvsp[(1) - (4)].str)))
			(yyval.output_rule)->val.section.ignored = true;
		      else
			(yyval.output_rule)->val.section.ignored = false;
		      (yyvsp[(3) - (4)].input_rule)->next = NULL;
		    }
    break;

  case 21:
#line 222 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      
		      (yyval.output_rule) = new_output_rule (output_section);
		      (yyval.output_rule)->val.section.name = (yyvsp[(1) - (2)].str);
		      (yyval.output_rule)->val.section.input = new_input_rule (input_section);
		      (yyval.output_rule)->val.section.input->next = NULL;
		      (yyval.output_rule)->val.section.input->val.section =
			(struct filemask_section_name *)
			  obstack_alloc (&ld_state.smem,
					 sizeof (struct filemask_section_name));
		      (yyval.output_rule)->val.section.input->val.section->filemask = NULL;
		      (yyval.output_rule)->val.section.input->val.section->excludemask = NULL;
		      (yyval.output_rule)->val.section.input->val.section->section_name =
			new_input_section_name ((yyvsp[(1) - (2)].str), false);
		      (yyval.output_rule)->val.section.input->val.section->keep_flag = false;
		      if (ld_state.strip == strip_debug
			  && ebl_debugscn_p (ld_state.ebl, (yyvsp[(1) - (2)].str)))
			(yyval.output_rule)->val.section.ignored = true;
		      else
			(yyval.output_rule)->val.section.ignored = false;
		    }
    break;

  case 22:
#line 246 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.assignment) = new_assignment ((yyvsp[(1) - (3)].str), (yyvsp[(3) - (3)].expr), false); }
    break;

  case 23:
#line 248 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.assignment) = new_assignment ((yyvsp[(3) - (6)].str), (yyvsp[(5) - (6)].expr), true); }
    break;

  case 24:
#line 252 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(2) - (2)].input_rule)->next = (yyvsp[(1) - (2)].input_rule)->next;
		      (yyval.input_rule) = (yyvsp[(1) - (2)].input_rule)->next = (yyvsp[(2) - (2)].input_rule);
		    }
    break;

  case 25:
#line 257 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.input_rule) = (yyvsp[(1) - (1)].input_rule); }
    break;

  case 26:
#line 261 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.input_rule) = new_input_rule (input_section);
		      (yyval.input_rule)->val.section = (yyvsp[(1) - (1)].filemask_section_name);
		    }
    break;

  case 27:
#line 266 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(3) - (4)].filemask_section_name)->keep_flag = true;

		      (yyval.input_rule) = new_input_rule (input_section);
		      (yyval.input_rule)->val.section = (yyvsp[(3) - (4)].filemask_section_name);
		    }
    break;

  case 28:
#line 273 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.input_rule) = new_input_rule (input_assignment);
		      (yyval.input_rule)->val.assignment = (yyvsp[(1) - (2)].assignment);
		    }
    break;

  case 29:
#line 280 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.filemask_section_name) = (struct filemask_section_name *)
			obstack_alloc (&ld_state.smem, sizeof (*(yyval.filemask_section_name)));
		      (yyval.filemask_section_name)->filemask = (yyvsp[(1) - (5)].str);
		      (yyval.filemask_section_name)->excludemask = (yyvsp[(3) - (5)].str);
		      (yyval.filemask_section_name)->section_name = (yyvsp[(4) - (5)].sectionname);
		      (yyval.filemask_section_name)->keep_flag = false;
		    }
    break;

  case 30:
#line 291 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.sectionname) = new_input_section_name ((yyvsp[(1) - (1)].str), false); }
    break;

  case 31:
#line 293 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.sectionname) = new_input_section_name ((yyvsp[(3) - (4)].str), true); }
    break;

  case 32:
#line 297 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.str) = (yyvsp[(3) - (4)].str); }
    break;

  case 33:
#line 299 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.str) = NULL; }
    break;

  case 34:
#line 303 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr (exp_align);
		      (yyval.expr)->val.child = (yyvsp[(3) - (4)].expr);
		    }
    break;

  case 35:
#line 308 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.expr) = (yyvsp[(2) - (3)].expr); }
    break;

  case 36:
#line 310 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr (exp_mult);
		      (yyval.expr)->val.binary.left = (yyvsp[(1) - (3)].expr);
		      (yyval.expr)->val.binary.right = (yyvsp[(3) - (3)].expr);
		    }
    break;

  case 37:
#line 316 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr ((yyvsp[(2) - (3)].op));
		      (yyval.expr)->val.binary.left = (yyvsp[(1) - (3)].expr);
		      (yyval.expr)->val.binary.right = (yyvsp[(3) - (3)].expr);
		    }
    break;

  case 38:
#line 322 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr ((yyvsp[(2) - (3)].op));
		      (yyval.expr)->val.binary.left = (yyvsp[(1) - (3)].expr);
		      (yyval.expr)->val.binary.right = (yyvsp[(3) - (3)].expr);
		    }
    break;

  case 39:
#line 328 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr (exp_and);
		      (yyval.expr)->val.binary.left = (yyvsp[(1) - (3)].expr);
		      (yyval.expr)->val.binary.right = (yyvsp[(3) - (3)].expr);
		    }
    break;

  case 40:
#line 334 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr (exp_or);
		      (yyval.expr)->val.binary.left = (yyvsp[(1) - (3)].expr);
		      (yyval.expr)->val.binary.right = (yyvsp[(3) - (3)].expr);
		    }
    break;

  case 41:
#line 340 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr (exp_num);
		      (yyval.expr)->val.num = (yyvsp[(1) - (1)].num);
		    }
    break;

  case 42:
#line 345 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyval.expr) = new_expr (exp_id);
		      (yyval.expr)->val.str = (yyvsp[(1) - (1)].str);
		    }
    break;

  case 43:
#line 350 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.expr) = new_expr (exp_sizeof_headers); }
    break;

  case 44:
#line 352 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.expr) = new_expr (exp_pagesize); }
    break;

  case 45:
#line 356 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(3) - (3)].filename_list)->next = (yyvsp[(1) - (3)].filename_list)->next;
		      (yyval.filename_list) = (yyvsp[(1) - (3)].filename_list)->next = (yyvsp[(3) - (3)].filename_list);
		    }
    break;

  case 46:
#line 361 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.filename_list) = (yyvsp[(1) - (1)].filename_list); }
    break;

  case 49:
#line 369 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      if ((yyvsp[(3) - (4)].filename_list) != (yyvsp[(3) - (4)].filename_list)->next)
			{
			  (yyvsp[(3) - (4)].filename_list)->next->group_start = 1;
			  (yyvsp[(3) - (4)].filename_list)->group_end = 1;
			}
		      (yyval.filename_list) = (yyvsp[(3) - (4)].filename_list);
		    }
    break;

  case 50:
#line 380 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.filename_list) = mark_as_needed ((yyvsp[(3) - (4)].filename_list)); }
    break;

  case 51:
#line 382 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.filename_list) = new_filename_listelem ((yyvsp[(1) - (1)].str)); }
    break;

  case 52:
#line 387 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(2) - (2)].version)->next = (yyvsp[(1) - (2)].version)->next;
		      (yyval.version) = (yyvsp[(1) - (2)].version)->next = (yyvsp[(2) - (2)].version);
		    }
    break;

  case 53:
#line 392 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.version) = (yyvsp[(1) - (1)].version); }
    break;

  case 54:
#line 396 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(2) - (4)].version)->versionname = "";
		      (yyvsp[(2) - (4)].version)->parentname = NULL;
		      (yyval.version) = (yyvsp[(2) - (4)].version);
		    }
    break;

  case 55:
#line 402 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(3) - (5)].version)->versionname = (yyvsp[(1) - (5)].str);
		      (yyvsp[(3) - (5)].version)->parentname = NULL;
		      (yyval.version) = (yyvsp[(3) - (5)].version);
		    }
    break;

  case 56:
#line 408 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      (yyvsp[(3) - (6)].version)->versionname = (yyvsp[(1) - (6)].str);
		      (yyvsp[(3) - (6)].version)->parentname = (yyvsp[(5) - (6)].str);
		      (yyval.version) = (yyvsp[(3) - (6)].version);
		    }
    break;

  case 57:
#line 417 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.version) = merge_versions ((yyvsp[(1) - (2)].version), (yyvsp[(2) - (2)].version)); }
    break;

  case 58:
#line 419 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.version) = (yyvsp[(1) - (1)].version); }
    break;

  case 59:
#line 423 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.version) = new_version (NULL, (yyvsp[(2) - (2)].id_list)); }
    break;

  case 60:
#line 425 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.version) = new_version ((yyvsp[(2) - (2)].id_list), NULL); }
    break;

  case 61:
#line 430 "/home/mark/src/elfutils/src/ldscript.y"
    {
		      struct id_list *newp = new_id_listelem ((yyvsp[(2) - (3)].str));
		      newp->next = (yyvsp[(1) - (3)].id_list)->next;
		      (yyval.id_list) = (yyvsp[(1) - (3)].id_list)->next = newp;
		    }
    break;

  case 62:
#line 436 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.id_list) = new_id_listelem ((yyvsp[(1) - (2)].str)); }
    break;

  case 63:
#line 440 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.str) = (yyvsp[(1) - (1)].str); }
    break;

  case 64:
#line 442 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.str) = (yyvsp[(1) - (1)].str); }
    break;

  case 65:
#line 446 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.str) = (yyvsp[(1) - (1)].str); }
    break;

  case 66:
#line 448 "/home/mark/src/elfutils/src/ldscript.y"
    { (yyval.str) = NULL; }
    break;


#line 2118 "ldscript.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


yyerrlab:
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {

      if (yychar <= YYEOF)
	{
	  
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  goto yyerrlab1;


yyerrorlab:

  if ( 0)
     goto yyerrorlab;

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


yyerrlab1:
  yyerrstatus = 3;	

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


yyacceptlab:
  yyresult = 0;
  goto yyreturn;

yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  
  return YYID (yyresult);
}


#line 451 "/home/mark/src/elfutils/src/ldscript.y"


static void
yyerror (const char *s)
{
  error (0, 0, (ld_scan_version_script
		? gettext ("while reading version script '%s': %s at line %d")
		: gettext ("while reading linker script '%s': %s at line %d")),
	 ldin_fname, gettext (s), ldlineno);
}


static struct expression *
new_expr (int tag)
{
  struct expression *newp = (struct expression *)
    obstack_alloc (&ld_state.smem, sizeof (*newp));

  newp->tag = tag;
  return newp;
}


static struct input_section_name *
new_input_section_name (const char *name, bool sort_flag)
{
  struct input_section_name *newp = (struct input_section_name *)
    obstack_alloc (&ld_state.smem, sizeof (*newp));

  newp->name = name;
  newp->sort_flag = sort_flag;
  return newp;
}


static struct input_rule *
new_input_rule (int tag)
{
  struct input_rule *newp = (struct input_rule *)
    obstack_alloc (&ld_state.smem, sizeof (*newp));

  newp->tag = tag;
  newp->next = newp;
  return newp;
}


static struct output_rule *
new_output_rule (int tag)
{
  struct output_rule *newp = (struct output_rule *)
    memset (obstack_alloc (&ld_state.smem, sizeof (*newp)),
	    '\0', sizeof (*newp));

  newp->tag = tag;
  newp->next = newp;
  return newp;
}


static struct assignment *
new_assignment (const char *variable, struct expression *expression,
		bool provide_flag)
{
  struct assignment *newp = (struct assignment *)
    obstack_alloc (&ld_state.smem, sizeof (*newp));

  newp->variable = variable;
  newp->expression = expression;
  newp->sym = NULL;
  newp->provide_flag = provide_flag;

  
  return newp;
}


static void
new_segment (int mode, struct output_rule *output_rule)
{
  struct output_segment *newp;

  newp
    = (struct output_segment *) obstack_alloc (&ld_state.smem, sizeof (*newp));
  newp->mode = mode;
  newp->next = newp;

  newp->output_rules = output_rule->next;
  output_rule->next = NULL;

  
  if (ld_state.output_segments == NULL)
    ld_state.output_segments = newp;
  else
    {
      newp->next = ld_state.output_segments->next;
      ld_state.output_segments = ld_state.output_segments->next = newp;
    }

  if (mode == 0 && ld_state.strip == strip_all)
    {
      struct output_rule *runp;

      for (runp = newp->output_rules; runp != NULL; runp = runp->next)
	if (runp->tag == output_section)
	  runp->val.section.ignored = true;
    }
}


static struct filename_list *
new_filename_listelem (const char *string)
{
  struct filename_list *newp;

  
  newp = (struct filename_list *) xcalloc (1, sizeof (*newp));
  newp->name = string;
  newp->next = newp;
  return newp;
}


static struct filename_list *
mark_as_needed (struct filename_list *listp)
{
  struct filename_list *runp = listp;
  do
    {
      runp->as_needed = true;
      runp = runp->next;
    }
  while (runp != listp);

  return listp;
}


static void
add_inputfiles (struct filename_list *fnames)
{
  assert (fnames != NULL);

  if (ld_state.srcfiles == NULL)
    ld_state.srcfiles = fnames;
  else
    {
      struct filename_list *first = ld_state.srcfiles->next;

      ld_state.srcfiles->next = fnames->next;
      fnames->next = first;
      ld_state.srcfiles->next = fnames;
    }
}


static _Bool
special_char_p (const char *str)
{
  while (*str != '\0')
    {
      if (__builtin_expect (*str == '*', 0)
	  || __builtin_expect (*str == '?', 0)
	  || __builtin_expect (*str == '[', 0))
	return true;

      ++str;
    }

  return false;
}


static struct id_list *
new_id_listelem (const char *str)
{
  struct id_list *newp;

  newp = (struct id_list *) obstack_alloc (&ld_state.smem, sizeof (*newp));
  if (str == NULL)
    newp->u.id_type = id_all;
  else if (__builtin_expect (special_char_p (str), false))
    newp->u.id_type = id_wild;
  else
    newp->u.id_type = id_str;
  newp->id = str;
  newp->next = newp;

  return newp;
}


static struct version *
new_version (struct id_list *local, struct id_list *global)
{
  struct version *newp;

  newp = (struct version *) obstack_alloc (&ld_state.smem, sizeof (*newp));
  newp->next = newp;
  newp->local_names = local;
  newp->global_names = global;
  newp->versionname = NULL;
  newp->parentname = NULL;

  return newp;
}


static struct version *
merge_versions (struct version *one, struct version *two)
{
  assert (two->local_names == NULL || two->global_names == NULL);

  if (two->local_names != NULL)
    {
      if (one->local_names == NULL)
	one->local_names = two->local_names;
      else
	{
	  two->local_names->next = one->local_names->next;
	  one->local_names = one->local_names->next = two->local_names;
	}
    }
  else
    {
      if (one->global_names == NULL)
	one->global_names = two->global_names;
      else
	{
	  two->global_names->next = one->global_names->next;
	  one->global_names = one->global_names->next = two->global_names;
	}
    }

  return one;
}


static void
add_id_list (const char *versionname, struct id_list *runp, _Bool local)
{
  struct id_list *lastp = runp;

  if (runp == NULL)
    
    return;

  
  runp = runp->next;
  assert (runp != NULL);
  lastp->next = NULL;

  do
    if (runp->u.id_type == id_str)
      {
	struct id_list *curp;
	struct id_list *defp;
	unsigned long int hval = elf_hash (runp->id);

	curp = runp;
	runp = runp->next;

	defp = ld_version_str_tab_find (&ld_state.version_str_tab, hval, curp);
	if (defp != NULL)
	  {
	    
	    while (strcmp (defp->u.s.versionname, versionname) != 0)
	      {
		if (defp->next == NULL)
		  {
		    
		    defp->next = curp;
		    curp->u.s.local = local;
		    curp->u.s.versionname = versionname;
		    curp->next = NULL;
		    defp = NULL;
		    break;
		  }

		defp = defp->next;
	      }

	    if (defp != NULL && defp->u.s.local != local)
	      error (EXIT_FAILURE, 0, versionname[0] == '\0'
		     ? gettext ("\
symbol '%s' is declared both local and global for unnamed version")
		     : gettext ("\
symbol '%s' is declared both local and global for version '%s'"),
		     runp->id, versionname);
	  }
	else
	  {
	    
	    ld_version_str_tab_insert (&ld_state.version_str_tab, hval, curp);

	    curp->u.s.local = local;
	    curp->u.s.versionname = versionname;
	    curp->next = NULL;
	  }
      }
    else if (runp->u.id_type == id_all)
      {
	if (local)
	  {
	    if (ld_state.default_bind_global)
	      error (EXIT_FAILURE, 0,
		     gettext ("default visibility set as local and global"));
	    ld_state.default_bind_local = true;
	  }
	else
	  {
	    if (ld_state.default_bind_local)
	      error (EXIT_FAILURE, 0,
		     gettext ("default visibility set as local and global"));
	    ld_state.default_bind_global = true;
	  }

	runp = runp->next;
      }
    else
      {
	assert (runp->u.id_type == id_wild);
	
	abort ();
      }
  while (runp != NULL);
}


static void
add_versions (struct version *versions)
{
  struct version *lastp = versions;

  if (versions == NULL)
    return;

  
  versions = versions->next;
  assert (versions != NULL);
  lastp->next = NULL;

  do
    {
      add_id_list (versions->versionname, versions->local_names, true);
      add_id_list (versions->versionname, versions->global_names, false);

      versions = versions->next;
    }
  while (versions != NULL);
}
