# Genesis homebrew ABI: ECX = door chosen (1..3), EDX = hidden door.
# EAX = 1 on a match, 0 on a miss. INT3 returns to the launcher.
.text
.globl entry
entry:
    xor %eax, %eax
    cmp %edx, %ecx
    jne done
    mov $1, %eax
done:
    int3
