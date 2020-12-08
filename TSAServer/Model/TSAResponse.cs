using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TSAServer.Model
{
    public class TSAResponse
    {
        public DateTime GeneratedTime { get; set; }

        public string TimeStampToken { get; set; }

        public List<TSACertificate> Certificates { get; set; }
    }

}
