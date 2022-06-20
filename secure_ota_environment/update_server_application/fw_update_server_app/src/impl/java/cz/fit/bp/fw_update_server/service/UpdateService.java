package cz.fit.bp.fw_update_server.service;

import cz.fit.bp.fw_update_server.dao.FirmwareImageRepository;
import cz.fit.bp.fw_update_server.data.DataSource;
import cz.fit.bp.fw_update_server.entity.FirmwareImage;
import cz.fit.bp.fw_update_server.entity.FirmwareImageWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@Service
public class UpdateService {

    @Autowired
    @Qualifier("fileSystemDataSource")
    private DataSource dataSource;

    @Autowired
    private FirmwareImageRepository firmwareImageRepository;

    private static Logger logger = LoggerFactory.getLogger(UpdateService.class);


    public FirmwareImageWrapper getNewestFirmwareManifestStream(String deviceType) throws IOException {
        FirmwareImage firmwareImage = firmwareImageRepository.findFirstByDeviceTypeOrderByIdDesc(deviceType);
        return new FirmwareImageWrapper(dataSource.getFileInputStream(firmwareImage.getId() + "." + firmwareImage.getImageFile() + ".manifest"), firmwareImage);
    }

    public FirmwareImageWrapper getNewestFirmwareBinaryStream(String deviceType) throws IOException {
        FirmwareImage firmwareImage = firmwareImageRepository.findFirstByDeviceTypeOrderByIdDesc(deviceType);
        return new FirmwareImageWrapper(dataSource.getFileInputStream(firmwareImage.getId() + "." + firmwareImage.getImageFile() + ".bin"), firmwareImage);
    }


    public void storeFirmwareImage(MultipartFile manifest, MultipartFile firmware, int id, String deviceType, String fwName) throws IOException {
        FirmwareImage fi = new FirmwareImage();
        fi.setImageFile(fwName);
        fi.setDeviceType(deviceType);
        fi.setId(id);
        fi.setFirmwareLength(firmware.getSize());
        fi.setManifestLength(manifest.getSize());
        firmwareImageRepository.save(fi);

        dataSource.storeFirmwareFile(manifest, id + "." + fwName + ".manifest");
        dataSource.storeFirmwareFile(firmware, id + "." + fwName + ".bin");

    }


}
