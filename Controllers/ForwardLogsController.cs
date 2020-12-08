using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.IO;
using Microsoft.Extensions.Configuration;

namespace jsonToCefParser.Controllers
{
    [ApiController]
    [Route("/api/[controller]")]
    public class ForwardLogsController : ControllerBase
    {
        private IConfiguration _configuration;
        private readonly ILogger<ForwardLogsController> _logger;
        private static string LogName = "Tanium";

        public ForwardLogsController(IConfiguration configuration, ILogger<ForwardLogsController> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        [HttpPost]
        public async Task<IActionResult> Post()
        {
            using (StreamReader reader = new StreamReader(Request.Body, Encoding.UTF8))
            {
                string requestBody = await reader.ReadToEndAsync();
                _logger.LogInformation("[INFO] Request received...");
                var datestring = DateTime.UtcNow.ToString("r");
                var jsonBytes = Encoding.UTF8.GetBytes(requestBody);
                string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
                string hashedString = BuildSignature(stringToHash, _configuration["sharedKey"], _logger);
                string signature = "SharedKey " + _configuration["customerId"] + ":" + hashedString;

                return PushLog(signature, datestring, requestBody, _logger);
            }
        }

        private static string BuildSignature(string message, string secret, ILogger<ForwardLogsController> _logger)
        {
            _logger.LogInformation("[INFO] Building signature...");
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = Convert.FromBase64String(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hash = hmacsha256.ComputeHash(messageBytes);
                _logger.LogInformation("[INFO] Signature has been build");
                return Convert.ToBase64String(hash);
            }
        }

        private static IActionResult PushLog(string signature, string date, string json, ILogger<ForwardLogsController> _logger)
        {
            try
            {
                _logger.LogInformation("[INFO] Pushing logs...");
                string url = "https://" + customerId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";

                System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                client.DefaultRequestHeaders.Add("Log-Type", LogName);
                client.DefaultRequestHeaders.Add("Authorization", signature);
                client.DefaultRequestHeaders.Add("x-ms-date", date);
                //client.DefaultRequestHeaders.Add("time-generated-field", TimeStampField);

                System.Net.Http.HttpContent httpContent = new StringContent(json, Encoding.UTF8);
                httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                Task<System.Net.Http.HttpResponseMessage> response = client.PostAsync(new Uri(url), httpContent);

                System.Net.Http.HttpContent responseContent = response.Result.Content;
                string result = responseContent.ReadAsStringAsync().Result;
                _logger.LogInformation("[INFO] Logs pushed");
                return new OkObjectResult(result);
            }
            catch (Exception excep)
            {
                _logger.LogInformation("[ERROR] " + excep.Message);
                return new BadRequestObjectResult(excep.Message);
            }
        }
    }
}
