using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TSAServer.Model
{
    public class TSAProvider
    {
        public string InternalCertFilePath { get; set; }
        public string CertPassword { get; set; }
        public string CertAlias { get; set; }
        public string KeyCertAlias { get; set; }
        public string TimestampRequestPolicy { get; set; }
    }
}
