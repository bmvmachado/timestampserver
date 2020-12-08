using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TSAServer.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TSAController : ControllerBase
    {
        private readonly ILogger<TSAController> _logger;

        public TSAController(ILogger<TSAController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IEnumerable<string> Get()
        {
            return null;
            
        }
    }
}
