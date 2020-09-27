using Newtonsoft.Json;
using System.IO;
using System.Security.AccessControl;
using System.Collections.Generic;

namespace SharpHound3.LdapWrappers
{
	#region Class FilePermissionEntry
	public enum FileType
	{
		Directory,
		File
	};

	class FileSystemItem : LdapWrapper
	{
		internal FileSystemItem(Share share, FileType type, string fullPath) : base(null)
		{
			string extension = null;
			this.Type = type;
			this.Share = share;
			this.ObjectIdentifier = fullPath.ToUpper();
			if (this.Type == FileType.File)
				extension = Path.GetExtension(ObjectIdentifier);
			this.Properties.Add("name", this.ObjectIdentifier);
			this.Properties.Add("extension", extension);
			this.Properties.Add("fullpath", fullPath);
			this.Properties.Add("shareid", share.ObjectIdentifier);
			this.Properties.Add("objectid", this.ObjectIdentifier);
			this.Properties.Add("type", this.Type.ToString());
		}

		[JsonIgnore]
		public Share Share { get; set; }

		[JsonIgnore]
		public FileType Type { get; set; }

		public bool Exists
		{
			get
			{
				return Directory.Exists(this.ObjectIdentifier);
			}
		}

		public FileSystemSecurity GetAccessControl()
        {
			FileSystemSecurity result = null;
			if (this.Exists)
			{
				DirectoryInfo directoryInfo = new DirectoryInfo(this.ObjectIdentifier);
				result = directoryInfo.GetAccessControl(AccessControlSections.Access);
			}
			return result;
		}
	}
    #endregion

    class Share : LdapWrapper
    {
        internal Share(Computer computer, string name) : base(null)
        {
            this.Computer = computer;
			this.ObjectIdentifier = string.Format(@"\\{0}\{1}", computer.DisplayName, name).ToUpper();

			this.Properties.Add("computerid", computer.ObjectIdentifier);
			this.Properties.Add("objectid", this.ObjectIdentifier);
			this.Properties.Add("name", this.ObjectIdentifier);
            this.Properties.Add("domain", computer.Domain);
        }

        [JsonIgnore]
        public Computer Computer { get; set; }

		[JsonIgnore]
		public string UncPath { get; set; }

		[JsonIgnore]
		public List<FileSystemItem> FileSystemItems { get; set; } = new List<FileSystemItem>();
	}
}
