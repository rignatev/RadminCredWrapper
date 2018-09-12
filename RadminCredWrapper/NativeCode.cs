using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RadminCredWrapper
{
    public static class NativeCode
    {
        #region Constants
        internal const int WM_SETTEXT = 0X000C;
        internal const int WM_KEYDOWN = 0x100;
        internal const int BM_CLICK = 0x00F5;
        #endregion Constants

        #region User32.dll
        [DllImport("User32.dll")]
        internal static extern int SendMessage(IntPtr hWnd, int uMsg, int wParam, string lParam);

        [DllImport("User32.dll", SetLastError = true)]
        internal static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("User32.dll")]
        public static extern IntPtr FindWindowEx(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

        [DllImport("User32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool SetForegroundWindow(IntPtr hWnd);
        #endregion User32.dll
    }
}
