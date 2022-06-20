package cz.fit.bp.fw_update_server.entity;

import java.io.InputStream;

/**
 * Wrapper class for firmware image, serves as internal DTO
 * */
public class FirmwareImageWrapper {

    private InputStream inputStream;

    private FirmwareImage firmwareImageData;

    public FirmwareImageWrapper(InputStream inputStream, FirmwareImage firmwareImageData) {
        this.inputStream = inputStream;
        this.firmwareImageData = firmwareImageData;
    }

    public InputStream getInputStream() {
        return inputStream;
    }

    public void setInputStream(InputStream inputStream) {
        this.inputStream = inputStream;
    }

    public FirmwareImage getFirmwareImageData() {
        return firmwareImageData;
    }

    public void setFirmwareImageData(FirmwareImage firmwareImageData) {
        this.firmwareImageData = firmwareImageData;
    }
}
