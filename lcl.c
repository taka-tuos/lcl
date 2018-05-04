#define STB_C_LEXER_IMPLEMENTATION
#include "stb_c_lexer.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void print_token(stb_lexer *lexer)
{
	switch (lexer->token) {
		case CLEX_id        : printf("_%s", lexer->string); break;
		case CLEX_eq        : printf("=="); break;
		case CLEX_noteq     : printf("!="); break;
		case CLEX_lesseq    : printf("<="); break;
		case CLEX_greatereq : printf(">="); break;
		case CLEX_andand    : printf("&&"); break;
		case CLEX_oror      : printf("||"); break;
		case CLEX_shl       : printf("<<"); break;
		case CLEX_shr       : printf(">>"); break;
		case CLEX_plusplus  : printf("++"); break;
		case CLEX_minusminus: printf("--"); break;
		case CLEX_arrow     : printf("->"); break;
		case CLEX_andeq     : printf("&="); break;
		case CLEX_oreq      : printf("|="); break;
		case CLEX_xoreq     : printf("^="); break;
		case CLEX_pluseq    : printf("+="); break;
		case CLEX_minuseq   : printf("-="); break;
		case CLEX_muleq     : printf("*="); break;
		case CLEX_diveq     : printf("/="); break;
		case CLEX_modeq     : printf("%%="); break;
		case CLEX_shleq     : printf("<<="); break;
		case CLEX_shreq     : printf(">>="); break;
		case CLEX_dqstring  : printf("\"%s\"", lexer->string); break;
		case CLEX_charlit   : printf("'%s'", lexer->string); break;
		case CLEX_intlit    : printf("#%ld", lexer->int_number); break;
		case CLEX_floatlit  : printf("%g", lexer->real_number); break;
		default:
			if (lexer->token >= 0 && lexer->token < 256)
				printf("%c", (int) lexer->token);
			else {
				printf("<<<UNKNOWN TOKEN %ld >>>\n", lexer->token);
			}
			break;
	}
}

typedef struct {
	int issigned, bits, isfunc, isptr;
	char *name;
} variable_desc;

variable_desc parse_variable(stb_lexer *lexer)
{
	variable_desc vdt;
	if(stb_c_lexer_get_token(lexer)) {
		if(lexer->token == CLEX_id) {
			char *p = lexer->string;
			if(lexer->string[0] == 'p') {
				//printf("[pointer] ");
				vdt.isptr = 1;
				p++;
			}
			char sig;
			int bit;
			sscanf(p, "%c%d", &sig, &bit);
			//printf("%ssigned,%dbit ", sig == 'u' ? "un" : "", bit);
			if(stb_c_lexer_get_token(lexer)) {
				if(lexer->token == CLEX_id) {
					//printf("name = \"%s\"", lexer->string);
					vdt.issigned = sig == 's' ? 1 : 0;
					vdt.bits = bit;
					vdt.name = strdup(lexer->string);
				}
			}
		}
	}
	
	return vdt;
}

int rank(char *op) {
	if (*op == '*' || *op == '/' || *op == '%') return 4;
	if (*op == '+' || *op == '-') return 5;
	if (*op == ':' || *op == '=') return 6;
	return 99;
}

#define pop() stack_pointer > 0 ? stack[--stack_pointer] : NULL
#define peek() stack_pointer > 0 ? stack[stack_pointer-1] : NULL
#define push(p) stack[stack_pointer++] = p

#define pop2() stack_pointer2 > 0 ? stack2[--stack_pointer2] : NULL
#define peek2() stack_pointer2 > 0 ? stack2[stack_pointer2-1] : NULL
#define push2(p) stack2[stack_pointer2++] = p

char** convert(char *token[], int length) {
	int n;
	char *pToken;
	char *stack[4096];
	int stack_pointer = 0;

	char** buffer = calloc(length+1, sizeof(char*));
	int nBuf = 0;

	for (n = 0; n < length; n++) {
		if (*token[n] == '_' || *token[n] == '#' || *token[n] == '\"') {
			buffer[nBuf++] = token[n];
		} else if (*token[n] == ')') {
			while ((pToken = pop()) != NULL && *pToken != '(')
				buffer[nBuf++] = pToken;
		} else if (*token[n] == '(') {
			push(token[n]);
		} else if (peek() == NULL) {
			push(token[n]);
		} else {
			while (peek() != NULL) {
				if (rank(token[n]) > rank(peek())) {
					buffer[nBuf++] = pop();
				} else {
					push(token[n]);
					break;
				}
			}
		}
	}

	while ((pToken = pop()) != NULL)
		buffer[nBuf++] = pToken;
	buffer[nBuf++] = NULL;
	return buffer;
}

void printRPN(char *buffer[]) {
	int n;
	for(n = 0; buffer[n] != NULL; n++)
		printf("%s ", buffer[n]);
}

typedef struct __ctl_valfunc ctl_valfunc;

typedef struct {
	variable_desc desc;
	ctl_valfunc *local;
} valfunc_t;

typedef struct __ctl_valfunc {
	valfunc_t pool[4096];
	int len;
} ctl_valfunc;

ctl_valfunc global_ctl;
ctl_valfunc *now_ctl;

int global_skip_num = 0;

valfunc_t *valfunc_add(ctl_valfunc *c, variable_desc desc)
{
	ctl_valfunc* local = (ctl_valfunc *)malloc(sizeof(ctl_valfunc));
	local->len = 0;
	c->pool[c->len].desc = desc;
	c->pool[c->len].local = local;
	c->len++;
	return local;
}

valfunc_t *valfunc_find(ctl_valfunc *c, char *name)
{
	for(int i = 0; i < c->len; i++) {
		if(strcmp(c->pool[i].desc.name, name) == 0) {
			return &(c->pool[i]);
		}
	}
	return NULL;
}

void print_ctl_valfunc(ctl_valfunc *root)
{
	for(int i = 0; i < root->len; i++) {
		variable_desc desc;
		desc = root->pool[i].desc;
		if(desc.isfunc) {
			print_ctl_valfunc(root->pool[i].local);
		} else {
			int dst_bits = desc.isptr ? 4 : desc.bits / 8;
			printf(".%s\n", desc.name);
			printf("\td%c #0\n", " bw d"[dst_bits]);
		}
	}
}

int main(int argc, char *argv[])
{
	FILE *f = fopen(argv[1],"rb");
	char *text = (char *) malloc(1 << 20);
	int len = f ? fread(text, 1, 1<<20, f) : -1;
	stb_lexer lex;
	if(len < 0) {
		fprintf(stderr, "Error opening file\n");
		free(text);
		fclose(f);
		return 1;
	}
	fclose(f);
	
	stb_lexer *lexer = &lex;
	
	int in_func_def = 0;
	int in_block = 0;
	char *in_func_name;
	
	stb_c_lexer_init(lexer, text, text+len, (char *) malloc(0x10000), 0x10000);
	
	now_ctl = &global_ctl;
	
	ctl_valfunc *stack[4096];
	int stack_pointer = 0;
	
	while(stb_c_lexer_get_token(lexer)) {
		if(lexer->token == CLEX_parse_error) {
			printf("\n<<<PARSE ERROR>>>\n");
			break;
		}
		
		switch(lexer->token) {
			case CLEX_id : {
				if(!strcmp(lexer->string,"var")) {
					//printf("var(");
					//if(in_func_def) printf("[function argments \"%s\"] ", in_func_name);
					//if(now_ctl != &global_ctl) printf("[local]");
					variable_desc desc = parse_variable(lexer);
					desc.isfunc = 0;
					//printf(")\n");
					if(in_func_def) valfunc_add(valfunc_find(now_ctl, in_func_name)->local, desc);
					else valfunc_add(now_ctl, desc);
				} else if(!strcmp(lexer->string,"fn")) {
					//printf("function(");
					variable_desc desc = parse_variable(lexer);
					in_func_def = 1;
					in_func_name = desc.name;
					desc.isfunc = 1;
					valfunc_add(now_ctl, desc);
					//printf(")\n");
					printf("\tglobal .%s\n", in_func_name);
				} else {
					int beginf = 0;
					//printf("expr(");
					char *expr[512];
					int expr_len = 0;
					memset(expr, 0, sizeof(expr));
					while(1) {
						if(!expr[expr_len]) expr[expr_len] = malloc(512);
						if(beginf) printf(" ");
						if(lexer->token == CLEX_id) {
							//printf("_%s", lexer->string);
							sprintf(expr[expr_len], "_%s", lexer->string);
							expr_len++;
						} else if(lexer->token >= 0 && lexer->token < 256) {
							if(lexer->token == ';') break;
							//printf("%c", lexer->token);
							sprintf(expr[expr_len], "%c", lexer->token);
							expr_len++;
						} else if(lexer->token == CLEX_intlit) {
							//printf("#%ld", lexer->int_number);
							sprintf(expr[expr_len], "#%ld", lexer->int_number);
							expr_len++;
						} else if(lexer->token == CLEX_dqstring) {
							//printf("\"%s\"", lexer->string);
							sprintf(expr[expr_len], "\"%s\"", lexer->string);
							expr_len++;
						}
						beginf = 1;
						if(!stb_c_lexer_get_token(lexer)) break;
					}
					//printf(")\n");
					//printf("expr_rpn(");
					char **buf = convert(expr, expr_len);
					//printRPN(buf);
					//printf(")\n");
					
					//char *stack2[4096];
					//int stack_pointer2 = 0;
					int arglen = 0;
					
					int dst_bits = 0;
					
					for(int n = 0; buf[n] != NULL; n++) {
						char *p = buf[n];
						
						if (*p == '_') {
							int ptr_access = 0;
							if(p[1] == '$') {
								ptr_access = 1;
								p++;
							}
							valfunc_t *c = valfunc_find(now_ctl, p+1);
							if(c) {
								printf("\tli .%s\n", p+1);
								if(!c->desc.isfunc) {
									printf("\tli #0\n");
									if(ptr_access) {
										printf("\tldd\n");
										printf("\tli #0\n");
									}
									if(n != 0) printf("\tldd\n");
									else dst_bits = c->desc.isptr && !ptr_access ? 4 : c->desc.bits / 8;
								}
							} else {
								printf("\tglobal .%s\n", p+1);
								printf("\tli .%s\n", p+1);
							}
							arglen++;
						} else if (*p == '#') {
							printf("\tli %s\n",p);
							arglen++;
						} else if (*p == '\"') {
							int n = global_skip_num;
							p++;
							p[strlen(p)-1] = 0;
							printf("\tli .skip_ascii%d\n", n);
							printf("\tb\n");
							printf(".ascii%d\n", n);
							printf("\t.ascii \'%s\'\n", p);
							printf(".skip_ascii%d\n", n);
							printf("\tli .ascii%d\n", n);
							arglen++;
							global_skip_num++;
						} else {
							if(*p != ',') {
								switch(*p) {
									case '=':
										printf("\tst%c\n", " bw d"[dst_bits]);
										break;
									case ':':
										printf("\tlr %%65\n");
										printf("\tli #%d\n", arglen * 4);
										printf("\tsub\n");
										printf("\tsr %%65\n");
										printf("\tsr %%1\n");
										printf("\tlr %%65\n");
										printf("\tli #%d\n", (arglen - 1) * 4);
										printf("\tadd\n");
										printf("\tlr %%1\n");
										arglen = 0;
										printf("\tc\n");
										break;
									case '+':
										printf("\tadd\n");
										arglen--;
										break;
									case '-':
										printf("\tsubi\n");
										arglen--;
										break;
									case '*':
										printf("\tmuli\n");
										arglen--;
										break;
									case '/':
										printf("\tdivi\n");
										arglen--;
										break;
									//default:
									//printf("\tdo(%s)\n", p);
								}
								//printf("\tdo(%s)\n", p);
							} else {
								
							}
						}
					}
					//printf("\n\n");
				}
			}
			break;
			default: {
				if(lexer->token == ';') {
					if(in_func_def) in_func_def = 0;
				}
				if(lexer->token == '{') {
					if(in_func_def) {
						printf(".%s\n", in_func_name);
						in_func_def = 0;
					}
					in_block++;
					push(now_ctl);
					now_ctl = valfunc_find(now_ctl, in_func_name)->local;
				}
				if(lexer->token == '}') {
					in_block--;
					if(in_block == 0) printf("\tb\n");
					now_ctl = pop();
				}
			}
		}
	}
	
	print_ctl_valfunc(&global_ctl);
	
	return 0;
}
