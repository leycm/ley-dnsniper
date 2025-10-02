package de.leycm.dnsniper.sub;

import de.leycm.dnsniper.DNSniperApiProvider;

import java.io.IOException;
import java.util.List;

public interface SubDomainScanner {

     default List<String> scanDomain(String rootDomain) throws IOException {
         return DNSniperApiProvider.get().scanSubDomain(rootDomain);
     }

}
