
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace DnsUpdater
{
    public class AliDnsUpdater : IDisposable
    {
        readonly HttpClient _httpClient = new HttpClient();
        
        const string AliyunDnsBaseUri = "https://alidns.aliyuncs.com/";
        const string UpdateRecordActionName = "UpdateDomainRecord";
        const string GetRecordsActionName = "DescribeDomainRecords";
        const string HttpMethod = "POST";


        private readonly string _accessKeyId;
        private readonly string _accessKeySecret;
        private readonly string _domainName;
        
        public AliDnsUpdater(string domain, string accessKeyId, string accessKeySecret)
        {
            _accessKeyId = accessKeyId;
            _accessKeySecret = accessKeySecret;
            _domainName = domain;
        }
        
        public void UpdateRecord(string name, string value)
        {
            var recordName = name == _domainName ? "@" : name;
            recordName = recordName.Replace(_domainName, "").TrimEnd('.');
            
            var latestRecord = GetLatestRecord(recordName);
            if (latestRecord == null)
            {
                throw new InvalidOperationException($"找不到现有的 {recordName} 解析记录");
            }

            if (string.Equals(latestRecord.Value, value, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            
            var parameters = new Dictionary<string, string>()
            {
                {"Action", UpdateRecordActionName},
                {"RecordId", latestRecord.RecordId},
                {"RR", recordName},
                {"Type", "A"},
                {"Value", value},
                {"TTL",  "600"}
            };

            var requestBody = SignRequestParameters(parameters);
            var resp = InvokeAliyunDnsAPI<AliyunDnsResponse>(UpdateRecordActionName, requestBody);
            if (string.IsNullOrEmpty(resp.RecordId))
            {
                throw new AliyunDnsException(UpdateRecordActionName + " (process failed)", null, null, resp);
            }
        }
        
        private AliyunDnsRecord GetLatestRecord(string rr)
        {
            var parameters = new Dictionary<string, string>()
            {
                {"Action", GetRecordsActionName},
                {"DomainName", _domainName},
                {"PageSize", "100"}
            };

            var requestBody = SignRequestParameters(parameters);
            var resp = InvokeAliyunDnsAPI<AliyunPagedRecordResults>(GetRecordsActionName, requestBody);
            if (resp.DomainRecords?.Record == null)
            {
                throw new AliyunDnsException(GetRecordsActionName + " (process failed)", null, null, resp);
            }

            return resp.DomainRecords.Record.FirstOrDefault(d => d.RR.Equals(rr, StringComparison.OrdinalIgnoreCase));
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }

        
        TResp InvokeAliyunDnsAPI<TResp>(string action, string signedParameters) where TResp : IResponse
        {
            string responseContent = null;
            var dnsResponse = default(TResp);
            try
            {
                if (_httpClient.DefaultRequestHeaders.UserAgent.Count < 1)
                {
                    _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36");
                }

                var postContent = new StringContent(signedParameters, Encoding.ASCII, "application/x-www-form-urlencoded");
                var response = _httpClient.PostAsync(AliyunDnsBaseUri, postContent).Result;

                responseContent = response.Content.ReadAsStringAsync().Result;
                dnsResponse = JsonConvert.DeserializeObject<TResp>(responseContent);
                dnsResponse._OriginalResponse = responseContent;
                return dnsResponse;
            }
            catch (HttpRequestException ex)
            {
                throw new AliyunDnsException(action, ex, responseContent, dnsResponse);
            }
            catch (WebException ex)
            {
                try
                {
                    string resp;
                    using (var sr = new StreamReader(ex.Response.GetResponseStream()))
                    {
                        resp = sr.ReadToEnd();
                    }

                    throw new AliyunDnsException(action, ex, resp, null);
                }
                catch
                {
                    throw ex;
                }
                    
            }
            catch (JsonException jsonException)
            {
                throw new AliyunDnsException(action, jsonException, responseContent, null);
            }
        }
        
        
        
        
        string SignRequestParameters(Dictionary<string, string> requestParameters)
        {
            var nonce = Guid.NewGuid().ToString("N").Substring(4, 8);
            var parameters = new Dictionary<string, string>
            {
                {"Format", "JSON"},
                {"Version", "2015-01-09"},
                {"SignatureMethod", "HMAC-SHA1"},
                {"SignatureVersion", "1.0"},
                {"AccessKeyId", _accessKeyId},
                {"SignatureNonce", nonce},
                {"Timestamp", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")}
            };

            foreach (var key in requestParameters.Keys)
            {
                parameters.Add(key, requestParameters[key]);
            }

            var signature = GenerateSignature(_accessKeySecret, parameters);
            parameters.Add("Signature", signature);

            return string.Join("&", parameters.Select(kv => $"{kv.Key}={WebUtility.UrlEncode(kv.Value)}"));
        }
    
        static string GenerateSignature(string accessKeySecret, Dictionary<string, string> parametersBeforeSign)
        {
            string Encode(string p)
            {
                return WebUtility.UrlEncode(p)
                                .Replace("+", "20%")
                                .Replace("*", "%2A")
                                .Replace("%7E", "~");
            }
            
            string Hmac(string val, string keySecret)
            {
                var bytes = Encoding.ASCII.GetBytes(val);
                var key = Encoding.ASCII.GetBytes(keySecret + "&");

                using (var hmacsha1 = new HMACSHA1(key))
                using (var stream = new MemoryStream(bytes))
                {
                    return Convert.ToBase64String(hmacsha1.ComputeHash(stream));
                }    
            }
                
            var encodedParameters = parametersBeforeSign
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => $"{Encode(kv.Key)}={Encode(kv.Value)}");
            
            var canonicalizedQueryString = string.Join("&", encodedParameters);
            var stringToSign = $"{HttpMethod}&%2F&{Encode(canonicalizedQueryString)}";
            return Hmac(stringToSign, accessKeySecret);
        }


        public interface IResponse
        {
            string _OriginalResponse { get;set; }
        }

        class AliyunDnsResponse : IResponse
        {
            public string RequestId { get; set; }
            public string RecordId { get; set; }
            
            public string HostId { get; set; }
            public string Code { get; set; }
            public string Message { get; set; }
            
            public string _OriginalResponse { get; set; }
        }
        
        class AliyunDnsRecord
        {
            public string Value { get; set; }
            public string RecordId { get; set; }
            
            public string RR { get; set; }
        }
        
        class AliyunPagedRecordResults : IResponse
        {
            public string RequestId { get; set; }
            public RecordsObject DomainRecords { get; set; }
            
            public string _OriginalResponse { get; set; }


            public class RecordsObject
            {
                public List<AliyunDnsRecord> Record { get; set; } 
            }
        }

        public class AliyunDnsException: Exception
        {
            public IResponse ResponseObject { get; set; }
            public string ResponseContent { get; set; }
            
            public AliyunDnsException(string apiAction, Exception exception, 
                string response, IResponse responseObject)
                : base($"Failed to request api {AliyunDnsBaseUri} with action {apiAction}", exception)
            {
                this.ResponseContent = response;
                this.ResponseObject = responseObject;
            }

            public string GetResponseMessage()
            {
                return !string.IsNullOrEmpty(ResponseContent) ? ResponseContent : ResponseObject?._OriginalResponse;
            }
        }
    }
}

