#include <assert.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "callconv.h"
#include "def.h"

static const char S_PROMPT_0[] = "What's your name?> ";
static const char S_HELLO_0[] = "It's all written in the Book of HGAME...\n";
static const char S_HELLO_1[] =
    "Somewhere in the labyrinth of instructions hid a long-lost relic.\n";
static const char S_HELLO_2[] = "An artifact cloaked in camouflage of twisted nonsense...\n";
static const char S_HELLO_3[] = "Something only the bestest reverse engineer can see through.\n";
static const char S_HELLO_4[] =
    "Now, sharpen your decompilers, %s, let the battle commence...\nPress ENTER to start.\n";
static const char S_END_0[] =
    "\x1b[33mYou don't see that coming and passed out... Good luck next time.\x1b[0m\n";
static const char S_END_1[] = "You finally reach the dungeon's deepest bottom.\n";
static const char S_END_2[] = "\x1b[31mYou feel as if there's something amiss...\x1b[0m\n";
static const char S_END_3[] = "You dream as if you reached the bottom of the dungeon...\n";
static const char S_END_4[] =
    "You spot a crumpled piece of paper on the ground. It says in some dark red ink:\n";
static const char S_END_5[] = "\x1b[31;4;3mtrust NOTHING but your OWN EYES.\x1b[0m\n";
static const char S_SKIP_0[] = "Maybe next time you'll come here in person...\n";

typedef struct Entity_ {
  char name[32];
  int hp;
  unsigned int atk;
  unsigned int dmg;
  unsigned int def;
  unsigned int dex;
} Entity_t;

static const uint8_t RAND_POOL[] = {0x64, 0x6a, 0x50, 0x17, 0x81, 0x7d, 0x6f, 0x1a, 0x87,
                                    0xb1, 0xa4, 0x00, 0x09, 0x03, 0xf8, 0x8d, 0xf8, 0x6b,
                                    0xdf, 0x32, 0x5f, 0x40, 0x90, 0x9c, 0xb8, 0x3d, 0x86,
                                    0x13, 0x26, 0xb7, 0x63, 0xf7, 0x74, 0xe8, 0x53, 0xed,
                                    0x58, 0x20, 0x4f, 0xd9, 0x99, 0x26, 0x21, 0x37, 0xde,
                                    0x35, 0x76, 0xc8, 0xbc, 0xd0, 0x6e};

static const Entity_t MONSTER_INIT[5] = {
    {"Dead Junk Code",          10, 95, 2,  0, 30},
    {"Self-Modifying Code",     20, 80, 4,  1, 50},
    {"Antidebugger",            30, 80, 8,  2, 55},
    {"Control Flow Flattening", 40, 75, 10, 5, 65},
    {"Virtualization",          50, 70, 25, 8, 30},
};
static Entity_t player = {"Player", 0, 0, 0, 0, 0};

static void gets(char *buf, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    char c;
    if (nopcall_3f_0r(SYS_read, 0, (uintptr_t)&c, 1, NOP_nop) != 1) {
      break;
    }
    if (c == '\n' || c == '\r') {
      break;
    }
    buf[i] = c;
  }
  buf[i] = '\0';
}

static unsigned int roll(size_t n, unsigned int m, bool max) {
  unsigned int result = rand() % (m + 1);
  for (size_t i = 1; i < n; i++) {
    unsigned int this_result = rand() % (m + 1);
    result = (max ? (this_result > result) : (this_result < result)) ? this_result : result;
  }
  return result;
}

static void print_stats(const Entity_t *entity) {
  char buf[256];
  size_t len = 0;
  len = snprintf(
      buf,
      sizeof(buf),
      "%s: HP=%d ATK=%u DMG=%u DEF=%u DEX=%u\n",
      entity->name,
      entity->hp,
      entity->atk,
      entity->dmg,
      entity->def,
      entity->dex
  );
  nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
}

int main(void) {
  char buf[256];
  size_t len = 0;
  const char P_PROMPT_0[] = "?";
  static uint8_t input[64];
  static uint8_t x[64];
  static uint8_t state[64];

  time_t t = time(NULL);
  srand(RAND_POOL[t % sizeof RAND_POOL]);
  nopcall_3f_1r(
      SYS_write, 1, (uintptr_t)S_PROMPT_0, sizeof(S_PROMPT_0) - 1, NOP_puts, (uintptr_t)P_PROMPT_0
  );
  gets(player.name, 31);
  player.name[0] = islower(player.name[0]) ? toupper(player.name[0]) : player.name[0];
  nopcall_3f_2r(
      SYS_write, 1, (uintptr_t)S_HELLO_0, sizeof(S_HELLO_0) - 1, NOP_gets, (uintptr_t)input, 63
  );
  nopcall_3f_0r(SYS_write, 1, (uintptr_t)S_HELLO_1, sizeof(S_HELLO_1) - 1, NOP_nop);
  nopcall_3f_3r(
      SYS_write,
      1,
      (uintptr_t)S_HELLO_2,
      sizeof(S_HELLO_2) - 1,
      NOP_pack,
      (uintptr_t)x,
      (uintptr_t)S_HELLO_0,
      (uintptr_t)S_PROMPT_0
  );
  nopcall_3f_0r(SYS_write, 1, (uintptr_t)S_HELLO_3, sizeof(S_HELLO_3) - 1, NOP_nop);
  len = snprintf(buf, sizeof(buf), S_HELLO_4, player.name);
  nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
  player.hp = 100;
  player.atk = roll(3, 40, false) + 50;
  player.dmg = roll(3, 6, true);
  player.def = roll(2, 3, true);
  player.dex = roll(2, 30, false) + 45;
  memcpy(state, x, sizeof state);
  print_stats(&player);
  nopcall_3f_0r(SYS_read, 0, (uintptr_t)buf, 1, NOP_nop);

  bool defeat = false;
  for (size_t i = 1; i <= 20; i++) {
    if (defeat) {
      len = snprintf(buf, sizeof(buf), "In the depth, dungeon level %zu awaits silently.\n", i + 1);
      nopcall_3f_2r(SYS_write, 1, (uintptr_t)buf, len, NOP_qr, (uintptr_t)state, (uintptr_t)state);
      nopcall_3f_3r(
          SYS_write,
          1,
          (uintptr_t)S_SKIP_0,
          sizeof(S_SKIP_0) - 1,
          NOP_permute,
          (uintptr_t)state,
          (uintptr_t)state,
          i % 2
      );
      continue;
    }
    len = snprintf(buf, sizeof(buf), "You come to dungeon level %zu.\n", i + 1);
    nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
    print_stats(&player);
    Entity_t monster = MONSTER_INIT[roll(2, 1 + i / 4, true) % 5];
    len = snprintf(buf, sizeof(buf), "You spotted a %s!\n", monster.name);
    nopcall_3f_2r(SYS_write, 1, (uintptr_t)buf, len, NOP_qr, (uintptr_t)state, (uintptr_t)state);
    print_stats(&monster);
    bool player_turn = true;
    while (player.hp > 0 && monster.hp > 0) {
      Entity_t *const attacker = player_turn ? &player : &monster;
      Entity_t *const defender = player_turn ? &monster : &player;

      if (player_turn) {
        len =
            snprintf(buf, sizeof(buf), "It's your turn, %s. Press ENTER to attack.\n", player.name);
        nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
        nopcall_3f_0r(SYS_read, 0, (uintptr_t)buf, 1, NOP_nop);
      }

      if (roll(1, 100, false) < attacker->atk) {
        len = snprintf(buf, sizeof(buf), "%s attacks %s!\n", attacker->name, defender->name);
        nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
        if (roll(1, 100, false)
            < (attacker->dex > defender->dex ? ((attacker->dex - defender->dex) * 2) : defender->dex
            )) {
          len = snprintf(buf, sizeof(buf), "%s dodges the incoming blow.\n", defender->name);
          nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
        } else {
          len = snprintf(buf, sizeof(buf), "%s is hit!\n", defender->name);
          nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
          defender->hp -= (roll(3, attacker->dmg, true) - roll(3, defender->def, false));
          print_stats(defender);
        }
      } else {
        len = snprintf(
            buf, sizeof(buf), "%s attacks %s, but misses.\n", attacker->name, defender->name
        );
        nopcall_3f_0r(SYS_write, 1, (uintptr_t)buf, len, NOP_nop);
      }

      player_turn = !player_turn;
    }
    if (player.hp <= 0) {
      nopcall_3f_3r(
          SYS_write,
          1,
          (uintptr_t)S_END_0,
          sizeof(S_END_0) - 1,
          NOP_permute,
          (uintptr_t)state,
          (uintptr_t)state,
          i % 2
      );
      defeat = true;
    } else {
      len = snprintf(
          buf,
          sizeof(buf),
          "\x1b[32mYou defeat the %s!\x1b[0m You have recovered some HP.\n",
          monster.name
      );
      nopcall_3f_3r(
          SYS_write, 1, (uintptr_t)buf, len, NOP_permute, (uintptr_t)state, (uintptr_t)state, i % 2
      );
      const int new_hp = player.hp + roll(2, monster.dmg + monster.dmg / 2, true);
      player.hp = new_hp > 100 ? 100 : new_hp;
      print_stats(&player);
    }
  }

  if (!defeat) {
    nopcall_3f_0r(SYS_write, 1, (uintptr_t)S_END_1, sizeof(S_END_1) - 1, NOP_nop);
    nopcall_3f_3r(
        SYS_write,
        1,
        (uintptr_t)S_END_2,
        sizeof(S_END_2) - 1,
        NOP_blkadd,
        (uintptr_t)x,
        (uintptr_t)state,
        (uintptr_t)x
    );
  } else {
    nopcall_3f_3r(
        SYS_write,
        1,
        (uintptr_t)S_END_3,
        sizeof(S_END_3) - 1,
        NOP_blkadd,
        (uintptr_t)x,
        (uintptr_t)state,
        (uintptr_t)x
    );
  }
  nopcall_3f_0r(SYS_write, 1, (uintptr_t)S_END_4, sizeof(S_END_4) - 1, NOP_nop);
  uint8_t last = nopcall_3f_0r(SYS_write, 1, (uintptr_t)S_END_5, sizeof(S_END_5) - 1, NOP_get_iv);
  nopcall_1f_0r(SYS_exit, 0, NOP_skip_128b);
  // clang-format off
  asm volatile(
    "hlt" ASM_LE
    ".fill 256, 1, 0x90" ASM_LE
    :
    :
    : "memory");
  // clang-format on
  for (size_t i = 0; i < sizeof input; i++) {
    input[i] ^= x[i];
    input[i] ^= last;
    last = input[i];
  }
  const long retval = nopcall_1f_3r(
      SYS_exit, 0, NOP_check, (uintptr_t)RAND_POOL, sizeof(RAND_POOL), (uintptr_t)input
  );
  const char P_HIDDEN_0[] = "All of a sudden, the floor under your feet shatters into pieces!";
  const char P_HIDDEN_1[] = "In front of you, a prismatic gemstone glitters.";
  const char P_HIDDEN_2[] =
      "Clenching it, you know that your name will be remembered in the annals of history.";
  if (retval > 0) {
    nopcall_3f_1r(
        SYS_write, 1, (uintptr_t)P_HIDDEN_0, sizeof(P_HIDDEN_0) - 1, NOP_puts, (uintptr_t)P_HIDDEN_0
    );
    nopcall_3f_1r(
        SYS_write, 1, (uintptr_t)P_HIDDEN_1, sizeof(P_HIDDEN_1) - 1, NOP_puts, (uintptr_t)P_HIDDEN_1
    );
    nopcall_3f_1r(
        SYS_write, 1, (uintptr_t)P_HIDDEN_2, sizeof(P_HIDDEN_2) - 1, NOP_puts, (uintptr_t)P_HIDDEN_2
    );
  } else {
    const char P_BAD_0[] = "You feel something is amiss...";
    nopcall_3f_1r(
        SYS_write, 1, (uintptr_t)P_BAD_0, sizeof(P_BAD_0) - 1, NOP_puts, (uintptr_t)P_BAD_0
    );
  }

  return 0;
}
