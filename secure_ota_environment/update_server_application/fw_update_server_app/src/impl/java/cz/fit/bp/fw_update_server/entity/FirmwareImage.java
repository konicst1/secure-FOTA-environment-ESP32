package cz.fit.bp.fw_update_server.entity;


import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
public class FirmwareImage {

    @Id
    @Column
    private Integer id;

    @Column(name = "image_file")
    private String imageFile;

    @Column(name = "device_type")
    private String deviceType;

    @Column(name = "manifest_length")
    private long manifestLength;

    @Column(name = "firmware_length")
    private long firmwareLength;


    public FirmwareImage() {

    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getImageFile() {
        return imageFile;
    }

    public void setImageFile(String imageFile) {
        this.imageFile = imageFile;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public void setDeviceType(String deviceType) {
        this.deviceType = deviceType;
    }

    public long getManifestLength() {
        return manifestLength;
    }

    public void setManifestLength(long manifestLength) {
        this.manifestLength = manifestLength;
    }

    public long getFirmwareLength() {
        return firmwareLength;
    }

    public void setFirmwareLength(long firmwareLength) {
        this.firmwareLength = firmwareLength;
    }
}
