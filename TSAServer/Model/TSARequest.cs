using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TSAServer.Model
{
    public class TSARequest
    {
        public string Data { get; set; }

        public TsaDataTypeEnum DataType { get; set; }
    }


    public enum TsaDataTypeEnum 
    {
        Data,
        Hash
    }
}
