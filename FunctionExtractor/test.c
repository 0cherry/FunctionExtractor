#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>
#include <malloc.h>
#include <winnt.h>

struct Results {
	int * A;
	int N;
};

struct Results CyclicRotation(int A[], int N, int K);
int OddOccurrencesInArray(int A[], int N);
int FrogJmp(int X, int Y, int D);
int PermMissingElem(int A[], int N);
int TapeEquilibrium(int A[], int N);
int PermCheck(int A[], int N);
int Nesting(char *S); //To do
int MaxDoubleSliceSum(int A[], int N);
void thirteen();

/*
int main() {
	int *p = malloc(sizeof(int));
	*p = 1000;
	printf("*p : %d\n", *p);
	printf("p : %x\n", p);
	printf("&p : %x\n", &p);
	int *q = &p;
	printf("*q : %x\n", (*q));
	printf("(int *)(*q) : %x\n", (int *)(*q));
	printf("*(int *)(*q) : %d\n", *(int *)(*q));

	thirteen();
	return 0;
}
*/

void thirteen() {
	int arr[5] = { 1, 2, 3, 4, 5 };
	int *p = arr;
	int i;
	for (i = 0; i < 5; i++) {
		*p += 2;
		p++;
	}
	for (i = 0; i < 5; i++) {
		printf("%d ", arr[i]);
	}
	printf("\n");

	int arr2[5] = { 1, 2, 3, 4, 5 };
	p = arr2;
	for (i = 0; i < 5/2; i++) {
		int tmp = *p;
		*p = arr2[4 - i];
		arr2[4 - i] = tmp;
		p++;
	}
	for (i = 0; i < 5; i++) {
		printf("%d ", arr2[i]);
	}
	printf("\n");
}

int MaxDoubleSliceSum(int A[], int N) {
	int i, tmp, result=0x80000000, start = 0, mid = 1, end = 2;

	if (N < 3)
		return 0;

	for (; start < N-2; start++) {
		for (; end < N; end++) {
			tmp = 0;
			for (i = start; i < end-1; i++) {
				if (i == start || i == mid || i == end)
					continue;
				tmp += A[i];
			}
			result = tmp > result ? tmp : result;
		}
		mid++;
		end++;
	}

	return result;
}

int Nesting(char *S) {
	int i;
	int S_length = strlen(S);
	char SubS[50];
	
	if (S_length == 0)
		return 1;
	else if (S_length == 1)
		return 0;

	if (S_length % 2)
		return 0;

	if (S[0] == '(' && S[S_length-1] == ')') {
		int SubS_length = sizeof(SubS);
		strncpy(SubS, sizeof(SubS), S + 1, S_length - 2);
		// strncpy_s(SubS, sizeof(SubS), S+1, S_length-2);
		
		/*
		SubS = malloc(sizeof(char)*(S_length - 2));
		for (i = 0; i < S_length - 2; i++) {
			*SubS = "";
		}
		*S++;
		for (i = 1; i < S_length - 1; i++) {
			*SubS++ = *S++;
		}
		*/
		// free(S);
		return Nesting(SubS);
	}

	for (i = 0; i < S_length; i++) {
		printf("%c ", S[i]);
	}

	return 0;
}

int PermCheck(int A[], int N) {
	int i;
	int o_sum;
	int max = 0;
	int sum = 0;
	
	//antiSum
	/*
	if (sizeof(A) < N)
		return 0;
	*/

	for (i = 0; i < N; i++) {
		sum += A[i];
		max = max > A[i] ? max : A[i];
	}
	o_sum = max*(max + 1) / 2;

	return o_sum - sum < 0 ? 0 :!(o_sum - sum);
}

int TapeEquilibrium(int A[], int N) {
	int i;
	int lhs = A[0];
	int rhs = 0;
	int min = 0x7FFFFFFF;
	for (i = 1; i < N; i++) {
		rhs += A[i];
	}

	for (i = 1; i < N; i++) {
		min = min < abs(lhs - rhs) ? min : abs(lhs - rhs);
		lhs += A[i];
		rhs -= A[i];
	}
	return min;
}

int PermMissingElem(int A[], int N) {
	int i;
	int result = (N + 2)*(N + 1) / 2;
	int result2 = 0;
	for (i = 0; i < N; i++) {
		//result -= A[i];
		result2 += A[i];
	}
	return result < 0 ? ~result + 1 : result;
}

int FrogJmp(int X, int Y, int D) {
	int max_jmp = (Y - X) / D + 1;
	return (Y - X) % D == 0 ? max_jmp - 1 : max_jmp;
}

int OddOccurrencesInArray(int A[], int N) {
	int i;
	int result = 0;
	for (i = 0; i < N; i++) {
		result ^= A[i];
	}
	return result;
}

struct Results CyclicRotation(int A[], int N, int K) {
	struct Results result;
	int i, j;
	int tmp;
	for (i = 0; i < N-K%N; i++) {
		for (j = 0; j < N-1; j++) {
			tmp = A[(j + 1) % N];
			A[(j + 1) % N] = A[j];
			A[j] = tmp;
		}
	}
	result.A = A;
	result.N = N;
	return result;
}