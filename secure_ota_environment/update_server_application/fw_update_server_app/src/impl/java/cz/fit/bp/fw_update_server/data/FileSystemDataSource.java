package cz.fit.bp.fw_update_server.data;

import javafx.scene.shape.Path;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

@Component
public class FileSystemDataSource implements DataSource{

    @Value("${filesystem_data_source.storage_directory}")
    private String storageDirectory;

    @Override
    public ByteArrayInputStream getFileInputStream(String fileName) throws IOException {
        File firmwareManifestFile = new File(storageDirectory + File.separator + fileName);
        return new ByteArrayInputStream(FileUtils.readFileToByteArray(firmwareManifestFile));
    }

    @Override
    public void storeFirmwareFile(MultipartFile file, String name) throws IOException {
        file.transferTo(Paths.get(storageDirectory + File.separator + name));
    }
}
