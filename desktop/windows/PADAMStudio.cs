// -*- coding: utf-8 -*-
// PADAM NOCTURNE Studio — Настольное приложение под Windows и системный трей
// Компилируется встроенным в Windows компилятором C# (csc.exe) без встроенного Chromium.
// Отображает иконку в системном трее Windows (NotifyIcon):
//   - «Память работает (действующих: N)»
//   - «Удержано на проверку: M»
//   - Последние записи памяти
//   - Кнопки: Открыть PADAM Studio (в изолированном окне --app), Запустить сон NOCTURNE, Выход.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace PadamDesktop
{
    public class StudioTrayForm : Form
    {
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;
        private System.Windows.Forms.Timer pollTimer;
        private Process apiProcess;

        private string host = "127.0.0.1";
        private int port = 8765;
        private string token = "";
        private string dbPath = "";
        private string userId = "";
        private bool spawnedApi = false;
        private bool selfTestMode = false;
        private string screenshotPath = "";

        private Label lblStatusTitle;
        private Label lblMetrics;
        private Label lblHeldWarn;
        private ListBox lstRecent;
        private Button btnOpenStudio;
        private Button btnOpenReview;
        private Button btnRunSleep;

        private int activeCount = 0;
        private int reviewCount = 0;
        private int conflictsCount = 0;
        private List<string> recentItems = new List<string>();

        public StudioTrayForm(string[] args)
        {
            ParseArgs(args);
            if (string.IsNullOrEmpty(token))
            {
                token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N").Substring(0, 16);
            }

            InitializeWindow();
            InitializeTray();
        }

        private void ParseArgs(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--port" && i + 1 < args.Length) int.TryParse(args[++i], out port);
                else if (a == "--host" && i + 1 < args.Length) host = args[++i];
                else if (a == "--token" && i + 1 < args.Length) token = args[++i];
                else if (a == "--db" && i + 1 < args.Length) dbPath = args[++i];
                else if (a == "--user" && i + 1 < args.Length) userId = args[++i];
                else if (a == "--self-test") selfTestMode = true;
                else if (a == "--screenshot" && i + 1 < args.Length) screenshotPath = args[++i];
            }
        }

        private Icon CreateBrandIcon()
        {
            Bitmap bmp = new Bitmap(32, 32);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.FromArgb(11, 15, 23));
                using (Pen pCyan = new Pen(Color.FromArgb(0, 210, 255), 2.5f))
                using (Pen pViolet = new Pen(Color.FromArgb(168, 85, 247), 2.0f))
                {
                    g.DrawEllipse(pCyan, 4, 4, 24, 24);
                    g.DrawEllipse(pViolet, 10, 10, 12, 12);
                }
            }
            return Icon.FromHandle(bmp.GetHicon());
        }

        private void InitializeWindow()
        {
            this.Text = "PADAM · NOCTURNE Studio — Настольный центр памяти";
            this.Size = new Size(560, 460);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(11, 15, 23);
            this.ForeColor = Color.FromArgb(241, 245, 249);
            this.Font = new Font("Segoe UI", 10f, FontStyle.Regular);
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.Icon = CreateBrandIcon();

            Panel header = new Panel();
            header.Dock = DockStyle.Top;
            header.Height = 76;
            header.BackColor = Color.FromArgb(17, 24, 39);
            header.Padding = new Padding(18, 14, 18, 10);

            lblStatusTitle = new Label();
            lblStatusTitle.Text = "🟢 Память PADAM работает · Локальная защита активна";
            lblStatusTitle.Font = new Font("Segoe UI Semibold", 12f, FontStyle.Bold);
            lblStatusTitle.ForeColor = Color.FromArgb(56, 189, 248);
            lblStatusTitle.AutoSize = true;
            lblStatusTitle.Location = new Point(18, 14);

            lblMetrics = new Label();
            lblMetrics.Text = "Подключение к локальному ядру памяти...";
            lblMetrics.ForeColor = Color.FromArgb(148, 163, 184);
            lblMetrics.AutoSize = true;
            lblMetrics.Location = new Point(18, 44);

            header.Controls.Add(lblStatusTitle);
            header.Controls.Add(lblMetrics);

            lblHeldWarn = new Label();
            lblHeldWarn.Text = "🛡 Удержано на проверку: 0";
            lblHeldWarn.Font = new Font("Segoe UI Semibold", 10.5f, FontStyle.Bold);
            lblHeldWarn.ForeColor = Color.FromArgb(251, 191, 36);
            lblHeldWarn.BackColor = Color.FromArgb(23, 32, 51);
            lblHeldWarn.Location = new Point(18, 90);
            lblHeldWarn.Size = new Size(508, 36);
            lblHeldWarn.TextAlign = ContentAlignment.MiddleLeft;
            lblHeldWarn.Padding = new Padding(10, 0, 0, 0);

            Label lblRecentHeader = new Label();
            lblRecentHeader.Text = "Последние записи в памяти (только чтение, без выполнения скриптов):";
            lblRecentHeader.ForeColor = Color.FromArgb(226, 232, 240);
            lblRecentHeader.AutoSize = true;
            lblRecentHeader.Location = new Point(18, 138);

            lstRecent = new ListBox();
            lstRecent.Location = new Point(18, 164);
            lstRecent.Size = new Size(508, 175);
            lstRecent.BackColor = Color.FromArgb(17, 24, 39);
            lstRecent.ForeColor = Color.FromArgb(241, 245, 249);
            lstRecent.BorderStyle = BorderStyle.FixedSingle;
            lstRecent.Font = new Font("Consolas", 9.5f, FontStyle.Regular);

            btnOpenStudio = new Button();
            btnOpenStudio.Text = "Открыть окно PADAM Studio";
            btnOpenStudio.Location = new Point(18, 356);
            btnOpenStudio.Size = new Size(210, 40);
            btnOpenStudio.BackColor = Color.FromArgb(14, 165, 233);
            btnOpenStudio.ForeColor = Color.FromArgb(8, 13, 26);
            btnOpenStudio.FlatStyle = FlatStyle.Flat;
            btnOpenStudio.Font = new Font("Segoe UI Semibold", 9.5f, FontStyle.Bold);
            btnOpenStudio.Click += (s, e) => OpenStudioApp("");

            btnOpenReview = new Button();
            btnOpenReview.Text = "На проверку";
            btnOpenReview.Location = new Point(238, 356);
            btnOpenReview.Size = new Size(135, 40);
            btnOpenReview.BackColor = Color.FromArgb(30, 41, 59);
            btnOpenReview.ForeColor = Color.FromArgb(251, 191, 36);
            btnOpenReview.FlatStyle = FlatStyle.Flat;
            btnOpenReview.Click += (s, e) => OpenStudioApp("review");

            btnRunSleep = new Button();
            btnRunSleep.Text = "Сон NOCTURNE";
            btnRunSleep.Location = new Point(383, 356);
            btnRunSleep.Size = new Size(143, 40);
            btnRunSleep.BackColor = Color.FromArgb(30, 41, 59);
            btnRunSleep.ForeColor = Color.FromArgb(241, 245, 249);
            btnRunSleep.FlatStyle = FlatStyle.Flat;
            btnRunSleep.Click += (s, e) => TriggerConsolidate();

            this.Controls.Add(header);
            this.Controls.Add(lblHeldWarn);
            this.Controls.Add(lblRecentHeader);
            this.Controls.Add(lstRecent);
            this.Controls.Add(btnOpenStudio);
            this.Controls.Add(btnOpenReview);
            this.Controls.Add(btnRunSleep);

            this.Load += OnFormLoad;
            this.FormClosing += OnFormClosing;
        }

        private void InitializeTray()
        {
            trayMenu = new ContextMenuStrip();
            trayMenu.BackColor = Color.FromArgb(17, 24, 39);
            trayMenu.ForeColor = Color.FromArgb(241, 245, 249);
            trayMenu.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);

            trayIcon = new NotifyIcon();
            trayIcon.Text = "PADAM Studio: память работает";
            trayIcon.Icon = this.Icon;
            trayIcon.ContextMenuStrip = trayMenu;
            trayIcon.Visible = true;
            trayIcon.DoubleClick += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; };

            RebuildTrayMenu();
        }

        private string TruncateAtWord(string text, int maxLen)
        {
            if (string.IsNullOrEmpty(text) || text.Length <= maxLen) return text;
            int cut = text.LastIndexOf(' ', maxLen);
            if (cut < maxLen / 2) cut = maxLen;
            return text.Substring(0, cut).TrimEnd(' ', ',', '.', ';', ':', '—', '-') + "…";
        }

        private void RebuildTrayMenu()
        {
            trayMenu.Items.Clear();

            var itemStatus = new ToolStripMenuItem(string.Format("🟢 Память работает (действующих: {0})", activeCount));
            itemStatus.ForeColor = Color.FromArgb(56, 189, 248);
            itemStatus.Font = new Font(trayMenu.Font, FontStyle.Bold);
            itemStatus.Click += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; };
            trayMenu.Items.Add(itemStatus);

            var itemHeld = new ToolStripMenuItem(string.Format("🛡 Удержано на проверку: {0}", reviewCount));
            itemHeld.ForeColor = Color.FromArgb(251, 191, 36);
            itemHeld.Click += (s, e) => OpenStudioApp("review");
            trayMenu.Items.Add(itemHeld);

            trayMenu.Items.Add(new ToolStripSeparator());

            var itemRecentHead = new ToolStripMenuItem("Последние записи:");
            itemRecentHead.ForeColor = Color.FromArgb(148, 163, 184);
            trayMenu.Items.Add(itemRecentHead);

            if (recentItems.Count == 0)
            {
                var emptyItem = new ToolStripMenuItem("  (нет записей)");
                emptyItem.ForeColor = Color.FromArgb(148, 163, 184);
                trayMenu.Items.Add(emptyItem);
            }
            else
            {
                foreach (string r in recentItems)
                {
                    string shortText = TruncateAtWord(r, 52);
                    var recItem = new ToolStripMenuItem("  • " + shortText);
                    recItem.ForeColor = Color.FromArgb(241, 245, 249);
                    recItem.Click += (s, e) => OpenStudioApp("feed");
                    trayMenu.Items.Add(recItem);
                }
            }

            trayMenu.Items.Add(new ToolStripSeparator());

            var itemOpen = new ToolStripMenuItem("Открыть PADAM Studio");
            itemOpen.Font = new Font(trayMenu.Font, FontStyle.Bold);
            itemOpen.Click += (s, e) => OpenStudioApp("");
            trayMenu.Items.Add(itemOpen);

            var itemWindow = new ToolStripMenuItem("Показать окно статуса");
            itemWindow.Click += (s, e) => { this.Show(); this.WindowState = FormWindowState.Normal; };
            trayMenu.Items.Add(itemWindow);

            var itemSleep = new ToolStripMenuItem("Запустить сон NOCTURNE");
            itemSleep.Click += (s, e) => TriggerConsolidate();
            trayMenu.Items.Add(itemSleep);

            trayMenu.Items.Add(new ToolStripSeparator());

            var itemExit = new ToolStripMenuItem("Выход");
            itemExit.Click += (s, e) => ExitApplication();
            trayMenu.Items.Add(itemExit);
        }

        private void OnFormLoad(object sender, EventArgs e)
        {
            EnsureBackendRunning();
            RefreshStatus();

            pollTimer = new System.Windows.Forms.Timer();
            pollTimer.Interval = 5000;
            pollTimer.Tick += (s, ev) => RefreshStatus();
            pollTimer.Start();

            if (selfTestMode)
            {
                var testTimer = new System.Windows.Forms.Timer();
                testTimer.Interval = 1200;
                testTimer.Tick += (s, ev) =>
                {
                    testTimer.Stop();
                    RefreshStatus();
                    if (!string.IsNullOrEmpty(screenshotPath))
                    {
                        CaptureFormScreenshot(screenshotPath);
                        string menuShot = screenshotPath.Replace(".png", "_tray_menu.png");
                        CaptureTrayMenuScreenshot(menuShot);
                    }
                    Console.WriteLine("SELF_TEST_OK active=" + activeCount + " review=" + reviewCount + " recent=" + recentItems.Count);
                    ExitApplication();
                };
                testTimer.Start();
            }
        }

        private void CaptureTrayMenuScreenshot(string outPath)
        {
            try
            {
                trayMenu.Show(this, new Point(120, 60));
                trayMenu.Refresh();
                Application.DoEvents();
                using (Bitmap bmp = new Bitmap(trayMenu.Width, trayMenu.Height))
                {
                    trayMenu.DrawToBitmap(bmp, new Rectangle(0, 0, trayMenu.Width, trayMenu.Height));
                    bmp.Save(outPath, ImageFormat.Png);
                }
                trayMenu.Close();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Menu screenshot error: " + ex.Message);
            }
        }

        private void CaptureFormScreenshot(string outPath)
        {
            try
            {
                this.Refresh();
                Application.DoEvents();
                using (Bitmap bmp = new Bitmap(this.Width, this.Height))
                {
                    this.DrawToBitmap(bmp, new Rectangle(0, 0, this.Width, this.Height));
                    string dir = Path.GetDirectoryName(outPath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    bmp.Save(outPath, ImageFormat.Png);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Screenshot error: " + ex.Message);
            }
        }

        private void EnsureBackendRunning()
        {
            if (PingBackend()) return;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "python";
                string dbArg = string.IsNullOrEmpty(dbPath) ? "" : ("--db \"" + dbPath + "\" ");
                string effectiveUser = userId;
                if (string.IsNullOrEmpty(effectiveUser) && !string.IsNullOrEmpty(dbPath) && dbPath.EndsWith("demo.db", StringComparison.OrdinalIgnoreCase))
                {
                    effectiveUser = "demo_architect";
                }
                string userArg = string.IsNullOrEmpty(effectiveUser) ? "" : ("--user \"" + effectiveUser + "\" ");
                psi.Arguments = string.Format("-m padam {0}{1}api --host {2} --port {3} --token {4}", dbArg, userArg, host, port, token);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.WorkingDirectory = @"E:\CODE\padam-nocturne";
                if (!string.IsNullOrEmpty(dbPath))
                {
                    psi.EnvironmentVariables["PADAM_DB"] = dbPath;
                    psi.EnvironmentVariables["PADAM_DB_PATH"] = dbPath;
                }
                apiProcess = Process.Start(psi);
                spawnedApi = true;

                for (int i = 0; i < 25; i++)
                {
                    if (PingBackend()) break;
                    Thread.Sleep(200);
                }
            }
            catch (Exception ex)
            {
                lblStatusTitle.Text = "⚠ Не удалось запустить локальный сервер python -m padam";
                lblMetrics.Text = ex.Message;
            }
        }

        private bool PingBackend()
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(string.Format("http://{0}:{1}/health", host, port));
                req.Timeout = 800;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return resp.StatusCode == HttpStatusCode.OK;
                }
            }
            catch
            {
                return false;
            }
        }

        private string ApiGet(string path)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(string.Format("http://{0}:{1}{2}", host, port, path));
            req.Method = "GET";
            req.Headers["Authorization"] = "Bearer " + token;
            req.Timeout = 2500;
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                return sr.ReadToEnd();
            }
        }

        private string ApiPost(string path, string jsonBody)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(string.Format("http://{0}:{1}{2}", host, port, path));
            req.Method = "POST";
            req.ContentType = "application/json; charset=utf-8";
            req.Headers["Authorization"] = "Bearer " + token;
            req.Timeout = 4000;
            byte[] bytes = Encoding.UTF8.GetBytes(jsonBody);
            req.ContentLength = bytes.Length;
            using (Stream st = req.GetRequestStream())
            {
                st.Write(bytes, 0, bytes.Length);
            }
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                return sr.ReadToEnd();
            }
        }

        private int ExtractJsonInt(string json, string key)
        {
            Match m = Regex.Match(json, "\"" + Regex.Escape(key) + "\"\\s*:\\s*(\\d+)");
            if (m.Success)
            {
                int v = 0;
                int.TryParse(m.Groups[1].Value, out v);
                return v;
            }
            return 0;
        }

        private List<string> ExtractRecentRecords(string json)
        {
            List<string> res = new List<string>();
            MatchCollection kinds = Regex.Matches(json, "\"kind\"\\s*:\\s*\"([^\"]+)\"");
            MatchCollection contents = Regex.Matches(json, "\"content\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            int count = Math.Min(kinds.Count, contents.Count);
            for (int i = 0; i < count && i < 6; i++)
            {
                string k = kinds[i].Groups[1].Value;
                string c = Regex.Unescape(contents[i].Groups[1].Value);
                res.Add("[" + k + "] " + c);
            }
            return res;
        }

        private void RefreshStatus()
        {
            try
            {
                string ovJson = ApiGet("/overview");
                activeCount = ExtractJsonInt(ovJson, "active");
                reviewCount = ExtractJsonInt(ovJson, "quarantined");
                conflictsCount = ExtractJsonInt(ovJson, "conflicts");

                string recJson = ApiGet("/records?view=active&limit=6&offset=0");
                recentItems = ExtractRecentRecords(recJson);

                lblStatusTitle.Text = "🟢 Память PADAM работает · Локальная защита активна";
                lblMetrics.Text = string.Format("Действующих записей: {0}   ·   Противоречий: {1}   ·   Порт: {2}", activeCount, conflictsCount, port);
                lblHeldWarn.Text = string.Format("🛡 Удержано на проверку: {0} (внешние записи ждут решения)", reviewCount);

                lstRecent.Items.Clear();
                foreach (string r in recentItems)
                {
                    lstRecent.Items.Add(TruncateAtWord(r, 56));
                }

                string tip = string.Format("PADAM: память работает ({0}) | На проверку: {1}", activeCount, reviewCount);
                trayIcon.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;
                RebuildTrayMenu();
            }
            catch (Exception ex)
            {
                lblStatusTitle.Text = "⚠ Ожидание ответа от локального сервера PADAM...";
                lblMetrics.Text = ex.Message;
            }
        }

        private void TriggerConsolidate()
        {
            try
            {
                ApiPost("/consolidate", "{}");
                RefreshStatus();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Не удалось запустить сон NOCTURNE: " + ex.Message, "PADAM Studio", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void OpenStudioApp(string tab)
        {
            string url = string.Format("http://{0}:{1}/studio#token={2}", host, port, token);
            string[] edgeCandidates = new string[]
            {
                @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                @"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                @"C:\Program Files (x86)\Microsoft\EdgeCore\157.0.4341.42\msedge.exe"
            };
            foreach (string exe in edgeCandidates)
            {
                if (File.Exists(exe))
                {
                    ProcessStartInfo psi = new ProcessStartInfo(exe, "--app=\"" + url + "\" --window-size=1380,880");
                    psi.UseShellExecute = false;
                    Process.Start(psi);
                    return;
                }
            }
            Process.Start(url);
        }

        private void OnFormClosing(object sender, FormClosingEventArgs e)
        {
            if (!selfTestMode && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                this.Hide();
                return;
            }
            CleanupProcesses();
        }

        private void CleanupProcesses()
        {
            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
                trayIcon = null;
            }
            if (spawnedApi && apiProcess != null)
            {
                try
                {
                    if (!apiProcess.HasExited) apiProcess.Kill();
                }
                catch { }
            }
        }

        private void ExitApplication()
        {
            selfTestMode = true;
            CleanupProcesses();
            Application.Exit();
        }

        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new StudioTrayForm(args));
        }
    }
}
