using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace uniauth_net
{
    public static class Extensions
    {
        /// <summary>
        /// Removes IE frame references from dummy callback url errors
        /// </summary>
        /// <param name="current">Current url</param>
        /// <returns>processed url without IE error</returns>
        public static Uri ProcessIEUrlErrors(this Uri current)
        {
            if (current.Authority.Equals("ieframe.dll", StringComparison.CurrentCultureIgnoreCase))
            {
                string currentStr = current.ToString();
                string processed = current.Fragment.Substring(1);
                return new Uri(processed);
            }
            return current;
        }
    }
}
