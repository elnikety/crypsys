
/*
* Licensed Materials - Property of IBM
*
* trousers - An open source TCG Software Stack
*
* (C) Copyright International Business Machines Corp. 2006
*
*/

#include <stdio.h>
#include <stdlib.h>

#include "../include/list.h"
#include "../include/Definitions.h"

list_ptr list_new( void) {
	list_ptr list = (list_ptr)malloc( sizeof( list_struct));

	if( list == NULL) return NULL;
	list->head = NULL;
	return list;
}

void list_add(list_ptr list, void *obj) {
	list->current = (node_t *) malloc (sizeof(struct _list_t));
	if (list->current == NULL) {
		return;
	}
	if( list->head == NULL) {
		list->head = list->current;
	} else
		list->previous->next = list->current;
	list->current->obj = obj;
	list->current->next = NULL;
	list->previous = list->current;
}

void list_dump(list_ptr list) {
	node_t *current;

	if( list->head == NULL) // if head has not been altered
		puts("no data"); // list is empty
	else {
		current = list->head; // go to first node
		do {
			printf("%d\n", (int)current->obj); // print value at current node
			current = current->next; // traverse through the list
		} while(current != NULL); // until current node is NULL
	}
}

void list_freeall(list_ptr list) {
	node_t *current = list->head; // go to first node
	node_t *next;

	if( list->head != NULL) {
		current = list->head; // go to first node
		do {
			next = current->next;
			free(current);
			current = next;
		} while(current != NULL); // until current node is NULL
	}
}


void BilInsert(BigIntList* list, BigInt *bi)
{
	list_add(list, bi);
}

void BillInsert(BigIntListList* llist, BigIntList* l)
{
	list_add(llist, l);
}

unsigned int
lengthBIL(BigIntList* list)
{
	int i;

	i = 0;
	void *itr = list;
	while(itr != NULL)
	{
		itr = ((BigIntList *) itr)->next;
		i++;
	}

	return i;
}

unsigned int
lengthBILL(BigIntListList*)
{
	int i;

	i = 0;
	void *itr = list;
	while(itr != NULL)
	{
		itr = ((BigIntListList *) itr)->next;
		i++;
	}

	return i;
}
