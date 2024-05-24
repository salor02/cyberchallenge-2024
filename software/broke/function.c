#include <cstring>

bool FUN(char *key,int id,int acc_id){  
    int iVar1;
  int iVar2;
  size_t key_len;
  byte current_letter;
  int iVar3;
  long letter_num;
  byte bVar4;
  long in_FS_OFFSET;
  bool bVar5;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_48 = 0x7a4728eb8fe0cb06;
  local_40 = 0x7d3a7e5b02977144;
  local_38 = 0xebcc19c2a2cdd4f6;
  local_30 = 0x1d1bb9c37d83f192;
  key_len = strlen(key);
  bVar5 = false;
  if ((((key_len == 0x20) && (key[4] == '-')) && (key[9] == '-')) && (key[0xe] == '-')) {
    FUN_0010125c();
    letter_num = 0;
    iVar3 = 0;
    bVar4 = 0;
    do {
      current_letter = key[letter_num];
      if (id != 0) {
        iVar1 = 0;
        do {
          iVar2 = iVar1;
          current_letter = current_letter ^ (&DAT_00105020)[iVar3 + iVar2 & 0xff];
          iVar1 = iVar2 + 1;
        } while (id != iVar2 + 1);
        iVar3 = iVar3 + 1 + iVar2;
      }
      bVar4 = bVar4 | current_letter ^ *(byte *)((long)&local_48 + letter_num);
      iVar3 = iVar3 + acc_id;
      letter_num = letter_num + 1;
    } while (letter_num != 0x20);
    bVar5 = bVar4 == 0;
  }
  return bVar5;
}

int main(){
    char* key[32];
    strcpy(key, "Hello, World!")
    int id = 1;
    int id_acc = 1;
    bool res = FUN(key, id, id_acc);  
}