package cz.fit.bp.fw_update_server.data;

import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * This interface represents a data source that connects the app to data storage
 * */
public interface DataSource {

    /**
     * @return ByteArrayInputStream of file with given name
     * @param fileName name of file to get inputstream of
     * @throws IOException
     * */
    public ByteArrayInputStream getFileInputStream(String fileName) throws IOException;

    /**
     * Stores given file with given name to linked data storage
     * @param file file to store to data storage
     * @param name stored file will be named by this param
     * */
    public void storeFirmwareFile(MultipartFile file, String name) throws IOException;


}
