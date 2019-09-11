// fpga_libusb.c :
//     Code to directly communicate with the FT601 without using a kernel driver. Works with :
//     - Xilinx SP605 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - Xilinx AC701 dev board flashed with PCILeech bitstream and FTDI UMFT601X-B addon-board.
//     - PCIeScreamer board flashed with PCILeech bitstream.
//
// Contribution by Jérémie Boutoille from Synacktiv - www.synacktiv.com
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libusb.h>

#include "device.h"
#include "fpga_libusb.h"

static libusb_context *usb_ctx = NULL;
static libusb_device_handle *device_handle = NULL;

int ftdi_GetChipConfiguration(libusb_device_handle *device, struct FT_60XCONFIGURATION *config) {
    int err;

    err = libusb_control_transfer(device,
        LIBUSB_RECIPIENT_DEVICE | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_IN,
        0xCF, // proprietary stuffz
        1, // value
        0, //index
        (void*) config,
        sizeof(struct FT_60XCONFIGURATION),
        1000
    );

    return err;
}

int ftdi_SetChipConfiguration(libusb_device_handle *device, struct FT_60XCONFIGURATION *config) {
    int err;

    err = libusb_control_transfer(device,
        LIBUSB_RECIPIENT_DEVICE | LIBUSB_REQUEST_TYPE_VENDOR | LIBUSB_ENDPOINT_OUT,
        0xCF, // proprietary stuffz
        0, // value
        0, //index
        (void*) config,
        sizeof(struct FT_60XCONFIGURATION),
        1000
    );

    return err;
}

int ftdi_SendCmdRead(libusb_device_handle *device, int size)
{
    int transferred = 0;
    struct ft60x_ctrlreq ctrlreq;

    memset(&ctrlreq, 0, sizeof(ctrlreq));
    ctrlreq.idx++;
    ctrlreq.pipe = FTDI_ENDPOINT_IN;
    ctrlreq.cmd = 1; // read cmd.
    ctrlreq.len = size;

    return libusb_bulk_transfer(device, FTDI_ENDPOINT_SESSION_OUT, (void*) &ctrlreq, sizeof(struct ft60x_ctrlreq), &transferred, 1000);
}

int fpga_get_chip_configuration(void *config) {
    int rc = 0;
    int err;
    
    err = ftdi_GetChipConfiguration(device_handle, config);

    if(err != sizeof(struct FT_60XCONFIGURATION)) {
        vprintfv("[-] cannot get chip config: %s\n", libusb_strerror(err));
        rc = -1;
    }

    return rc;
}

int fpga_set_chip_configuration(void *config) {
    int rc = 0;

    if(ftdi_SetChipConfiguration(device_handle, config) != LIBUSB_SUCCESS) {
        rc = -1;
    }

    return rc;
}

int fpga_open(void)
{
    int rc = 0;
    ssize_t device_count;
    libusb_device **device_list;
    libusb_device *device;
    struct libusb_device_descriptor desc;
    int err;
    int i;
    int found;
    struct FT_60XCONFIGURATION chip_configuration;
    unsigned char string[255] = {0};
    char description[255] = {0};

    if(libusb_init(&usb_ctx)) {
        rc = -1;
        goto out;
    }

    device_count = libusb_get_device_list(usb_ctx, &device_list);
    if(device_count < 0) {
        vprintfv("[-] Cannot get device list: %s\n", libusb_strerror(device_count));
        rc = -1;
        goto out;
    }

    found = 0;
    for(i=0; i<device_count; i++) {
        device = device_list[i];

        err = libusb_get_device_descriptor(device, &desc);
        if(err != 0) {
            vprintfv("[-] Cannot get device descriptor: %s\n", libusb_strerror(err));
            rc = -1;
            goto out_free;
        }

        if(desc.idVendor == FTDI_VENDOR_ID && desc.idProduct == FTDI_FT60X_PRODUCT_ID) {
            vprintfv("[+] using FTDI device: %04x:%04x (bus %d, device %d)\n", 
                desc.idVendor,
                desc.idProduct,
                libusb_get_bus_number(device),
                libusb_get_device_address(device));
            found = 1;
            break;
        }

    }

    if(!found) {
        rc = -1;
        goto out_free;
    }

    err = libusb_open(device, &device_handle);
    if(err != 0) {
        vprintfv("[-] Cannot get device: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }

    err = libusb_reset_device(device_handle);
    if(err != 0) {
        vprintfv("[-] Cannot reset device: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }

    err = libusb_get_string_descriptor_ascii(device_handle, desc.iManufacturer, string, sizeof(string));
    if(err > 0) {
        snprintf(description, sizeof(description), "%s - ", string);
    } else {
        snprintf(description, sizeof(description), "%04X - ", desc.idVendor);
    }

    err = libusb_get_string_descriptor_ascii(device_handle, desc.iProduct, string, sizeof(string));
    if(err > 0) {
        snprintf(description + strlen(description), sizeof(description), "%s", string);
    } else {
        snprintf(description + strlen(description), sizeof(description), "%04X", desc.idProduct);
    }

    err = libusb_get_string_descriptor_ascii(device_handle, desc.iSerialNumber, string, sizeof(string));
    if(err > 0) {
        snprintf(description + strlen(description), sizeof(description), " - serialNumber %s", string);
    }

    vprintfv("[+] %s\n", description);

    err = ftdi_GetChipConfiguration(device_handle, &chip_configuration);
    if(err != sizeof(chip_configuration)) {
        vprintfv("[-] Cannot get chio configuration: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }


    if( chip_configuration.FIFOMode != CONFIGURATION_FIFO_MODE_245 ||
        chip_configuration.ChannelConfig != CONFIGURATION_CHANNEL_CONFIG_1 ||
        chip_configuration.OptionalFeatureSupport != CONFIGURATION_OPTIONAL_FEATURE_DISABLEALL
      ) {
        vprintfv("[!] Bad FTDI configuration... setting chip config to fifo 245 && 1 channel, no feature support\n");

        chip_configuration.FIFOMode = CONFIGURATION_FIFO_MODE_245;
        chip_configuration.ChannelConfig = CONFIGURATION_CHANNEL_CONFIG_1;
        chip_configuration.OptionalFeatureSupport = CONFIGURATION_OPTIONAL_FEATURE_DISABLEALL;

        err = ftdi_SetChipConfiguration(device_handle, &chip_configuration);
        if(err != sizeof(chip_configuration)) {
            vprintfv("[-] Cannot set chip configuration: %s\n", libusb_strerror(err));
            rc = -1;
            goto out_free;
        }

    }

    err = libusb_kernel_driver_active(device_handle, FTDI_COMMUNICATION_INTERFACE);
    if(err < 0) {
        vprintfv("[-] Cannot get kernel driver status for FTDI_COMMUNICATION_INTERFACE: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }

    if(err) {
        vprintfv("[-] driver is active on FTDI_COMMUNICATION_INTERFACE = %d\n", err);
        rc = -1;
        goto out_free;
    }

    err = libusb_kernel_driver_active(device_handle, FTDI_DATA_INTERFACE);
    if(err < 0) {
        vprintfv("[-] Cannot get kernel driver status for FTDI_DATA_INTERFACE: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }

    if(err) {
        vprintfv("[-] driver is active on FTDI_DATA_INTERFACE = %d\n", err);
        rc = -1;
        goto out_free;
    }

    err = libusb_claim_interface(device_handle, FTDI_COMMUNICATION_INTERFACE);
    if(err != 0) {
        vprintfv("[-] Cannot claim interface FTDI_COMMUNICATION_INTERFACE: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }

    err = libusb_claim_interface(device_handle, FTDI_DATA_INTERFACE);
    if(err != 0) {
        vprintfv("[-] Cannot claim interface FTDI_DATA_INTERFACE: %s\n", libusb_strerror(err));
        rc = -1;
        goto out_free;
    }

out_free:
    libusb_free_device_list(device_list, 1);

out:
    
    return rc;
}

int fpga_close(void)
{
    libusb_close(device_handle);
    libusb_exit(usb_ctx);

    device_handle = NULL;
    usb_ctx = NULL;

    return 0;
}

int fpga_read(void *data, int size, int *transferred)
{
    int err;

    err = ftdi_SendCmdRead(device_handle, size);
    if(err) {
        vprintfv("[-] cannot send CmdRead ftdi: %s", libusb_strerror(err));
        return -1;
    }

    *transferred = 0;
    err = libusb_bulk_transfer(device_handle, FTDI_ENDPOINT_IN, data, size, transferred, 0);
    if(err < 0) {
        vprintfv("[-] bulk transfer error: %s", libusb_strerror(err));
        return -1;
    }

    // Commented out because in that case, size is a max size.
    // Caller should check the transferred value
    // if(*transferred != size) {
    //  rc = PCILEECH_ERROR_TRANSFER_NOT_COMPLETE;
    //  goto end;
    // }

    return 0;
}

int fpga_write(void *data, int size, int *transferred)
{
    int err;
    
    *transferred = 0;
    err = libusb_bulk_transfer(device_handle, FTDI_ENDPOINT_OUT, data, size, transferred, 1000);

    if(err < 0) {
        vprintfv("[-] bulk transfer error: %s", libusb_strerror(err));
        return -1;
    }

    if(*transferred != size) {
        vprintfv("[-] only %d bytes transferred\n", *transferred);
        return -1;
    }

    return 0;
}
