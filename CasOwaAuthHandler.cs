#region License
/*
 * Copyright © 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#endregion

using System;
using System.Configuration;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Text;
using System.Web;
using System.Web.SessionState;
using System.Xml;
using DotNetCasClient;
using DotNetCasClient.Security;
using log4net;
using log4net.Config;

namespace CasOwa
{
    /// <summary>
    /// CasOwaAuthHandler provides Jasig CAS Authentiction for Microsoft Outlook Web Access.
    /// </summary>
    public sealed class CasOwaAuthHandler : IHttpHandler, IRequiresSessionState
    {
        #region Fields

        /// <summary>
        /// URL of CAS ClearPass extension
        /// </summary>
        private static string ClearPassUrl;

        /// <summary>
        /// URL of CAS ClearPass extension as Uri for DotNetClient API call
        /// </summary>
        private static Uri ClearPassUri;

        /// <summary>
        /// CAS protocol artifact name
        /// </summary>
        private static string ArtifactParameterName = "ticket";

        /// <summary>
        /// CAS protocol service name
        /// </summary>
        private static string ServiceParameterName = "service";

        /// <summary>
        /// Base URL for OWA, e.g. https://hostname/owa
        /// </summary>
        private static string OwaUrl;

        /// <summary>
        /// URL for OWA Auth, used to start an OWA session and retrieve sessionid and cadata.
        /// </summary>
        private static string OwaAuthUrl;

        /// <summary>
        /// Option Form Fields from the OWA authentication form.
        /// </summary>
        private static string OwaOptionalFormFields = "&flags=0&forcedownlevel=0";

        /// <summary>
        /// Path to OWA Auth script.
        /// </summary>
        private static string OwaAuthPath = "/auth/owaauth.dll";

        /// <summary>
        /// OWA Inbox Redirect after authentication
        /// </summary>
        private static string OwaInboxUrl;

        private static readonly ILog log = null;

        #endregion

        #region Static Constructor

        static CasOwaAuthHandler()
        {

            XmlConfigurator.Configure();
            log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

            ClearPassUrl = ConfigurationManager.AppSettings.Get("CasOwa.ClearPassUrl");
            if (String.IsNullOrEmpty(ClearPassUrl))
            {

                Exception ex = new ConfigurationErrorsException("ClearPassUrl is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"ClearPassUrl\" value=\"https://cashostname/cas/clearPass\"/>");
                if (log.IsErrorEnabled)
                    log.Error(ex.Message, ex);
                throw ex;
            }

            try
            {
                ClearPassUri = new Uri(ClearPassUrl);
            }
            catch (UriFormatException ufe)
            {
                Exception ex = new ConfigurationErrorsException("ClearPassUrl is invalid.  Check your settings in <appSettings> section of <web.conf>. " + ufe.Message, ufe);
                if (log.IsErrorEnabled)
                    log.Error(ex.Message, ex);
                throw ex;
            }

            ArtifactParameterName = ConfigurationManager.AppSettings.Get("CasOwa.ArtifactParameterName") ?? ArtifactParameterName;
            ServiceParameterName = ConfigurationManager.AppSettings.Get("CasOwa.ServiceParameterName") ?? ServiceParameterName;

            OwaUrl = ConfigurationManager.AppSettings.Get("CasOwa.OwaUrl");
            if (String.IsNullOrEmpty(OwaUrl))
            {
                Exception ex = new ConfigurationErrorsException("CasOwa.OwaUrl is missing. It must be set in <appSettings> section of <web.conf>.  Example: <add key=\"CasOwa.OwaAuthUrl\" value=\"https://exchangehostname/owa\"/>");
                if (log.IsErrorEnabled)
                    log.Error(ex.Message, ex);
                throw ex;
            }

            OwaAuthPath = ConfigurationManager.AppSettings.Get("CasOwa.OwaAuthPath") ?? OwaAuthPath;
            OwaAuthUrl = OwaUrl + OwaAuthPath;

            OwaOptionalFormFields = ConfigurationManager.AppSettings.Get("CasOwa.OwaOptionalFormFields") ?? OwaOptionalFormFields;

            OwaInboxUrl = ConfigurationManager.AppSettings.Get("CasOwa.OwaInboxUrl");

            // This is setting is necessary when using untrusted certificates, typically in a development or testing.
            var skipOwaUrlCertificateValidation = ConfigurationManager.AppSettings.Get("CasOwa.skipOwaUrlCertificateValidation");
            if (!String.IsNullOrEmpty(skipOwaUrlCertificateValidation) && bool.Parse(skipOwaUrlCertificateValidation))
                ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });

        }
        #endregion

        #region Properties
        /// <summary>
        /// This handler can be used for another request, as no state information is preserved per request.
        /// </summary>
        public bool IsReusable
        {
            get { return true; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Using ProxyTickets and the ClearPass extension for CAS CasOwaAuthHandler retrieves
        /// the users credentials, POSTs them to the OWA, retrieves sessionid and cdata cookies,
        /// sets them on the browser and redirects to the user's inbox.
        /// </summary>
        /// <param name="context"></param>
        public void ProcessRequest(HttpContext context)
        {
            ICasPrincipal user = context.User as ICasPrincipal;
            if (user == null)
                throw new HttpException(500, "HttpContext.Current.User is null.  Check that the DotNetCasClient is mapped and configured correctly in <web.conf>");


            // Retrieve a Proxy Ticket for ClearPass
            string proxyTicket = CasAuthentication.GetProxyTicketIdFor(ClearPassUrl);
            if (log.IsDebugEnabled)
                log.Debug("Proxy ticket received for clearpass: " + proxyTicket);


            // Get the Password from ClearPass
            string clearPassRequest = ClearPassUrl + "?" + ArtifactParameterName + "=" + proxyTicket + "&" + ServiceParameterName + "=" + ClearPassUrl;
            string clearPassResponse;

            try
            {
                using (StreamReader reader = new StreamReader(new WebClient().OpenRead(clearPassRequest)))
                    clearPassResponse = reader.ReadToEnd();
            }
            catch (Exception ex)
            {
                throw new HttpException(500, "Error getting response from clearPass at URL: " + clearPassRequest + ". " + ex.Message, ex);
            }

            string clearPass = XmlUtils.GetTextForElement(clearPassResponse, "cas:credentials");
            if (String.IsNullOrEmpty(clearPass))
                throw new HttpException(500, "Received response from " + clearPassRequest + ", but cas:credientials IsNullOrEmpty.  Check CAS server logs for errors.  Make sure SSL certs are trusted.");

            // POST username/password to owaauth.dll to get sessionid and cadata cookies
            var owaAuthFormFields = "destination=" + OwaUrl
                                  + "&username=" + user.Identity.Name
                                  + "&password=" + HttpUtility.UrlEncode(clearPass, Encoding.ASCII)
                                  + OwaOptionalFormFields;


            byte[] postData = Encoding.UTF8.GetBytes(owaAuthFormFields);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(OwaUrl + OwaAuthPath);

            request.AllowAutoRedirect = false;
            request.CookieContainer = new CookieContainer();
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = postData.Length;
            request.UserAgent = "Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+WOW64;+Trident/5.0)";

            try
            {
                using (Stream requestStream = request.GetRequestStream())
                    requestStream.Write(postData, 0, postData.Length);
            }
            catch (Exception ex)
            {
                if (log.IsErrorEnabled)
                    log.Error(ex.Message, ex);

                throw new HttpException(500, "Error POSTing Auth Form to " + OwaUrl + OwaAuthPath + ". " + ex.Message, ex);
            }

            try
            {
                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                {
                    if (log.IsDebugEnabled)
                        log.Debug("# of OWA cookies received: " + response.Cookies.Count);


                    // Send sessionid and cadata cookies back to the browser and redirect to Owa
                    foreach (Cookie cookie in response.Cookies)
                        context.Response.Cookies.Add(new HttpCookie(cookie.Name, cookie.Value));

                    string redirectUrl;
                    if (String.IsNullOrEmpty(OwaInboxUrl))
                        redirectUrl = response.GetResponseHeader("Location");
                    else
                        redirectUrl = OwaInboxUrl;

                    if (log.IsDebugEnabled)
                        log.Debug("Added all auth cookies. Redirecting to " + redirectUrl);

                    context.Response.Redirect(redirectUrl);
                }

            }
            catch (Exception ex)
            {
                if (log.IsErrorEnabled)
                    log.Error(ex.Message, ex);

                throw new HttpException(500, "Error getting Response from " + OwaUrl + OwaAuthPath + ". " + ex.Message, ex);

            }
        }
        #endregion

        #region Inner Classes

        private sealed class XmlUtils
        {
            /// <summary>
            /// Access to the log file
            /// </summary>
            static ILog LOG = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

            /// <summary>
            /// Parses the text for a specified element, assuming that there is at most one such
            /// element
            /// </summary>
            /// <param name="xmlAsString">the xml to be parsed</param>
            /// <param name="qualifiedElementName">the element to match,qualified with namespace</param>
            /// <returns>the text value of the element</returns>
            public static string GetTextForElement(string xmlAsString, string qualifiedElementName)
            {
                string elementText = null;
                if (!String.IsNullOrEmpty(xmlAsString) && !String.IsNullOrEmpty(qualifiedElementName))
                {
                    using (TextReader textReader = new StringReader(xmlAsString))
                    {
                        XmlReaderSettings settings = new XmlReaderSettings();
                        settings.ConformanceLevel = ConformanceLevel.Auto;
                        settings.IgnoreWhitespace = true;
                        using (XmlReader reader = XmlReader.Create(textReader, settings))
                        {
                            bool foundElement = reader.ReadToFollowing(qualifiedElementName);

                            if (foundElement)
                                elementText = reader.ReadElementString();
                        }
                    }
                }
                return elementText;
            }
        }

        #endregion
    }



}

