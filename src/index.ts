import { parseString } from 'xml2js';
export type Scan = {
  policy: Policy;
  reports: Report[];
};

type Report = {
  reportItems: ReportItem[];
  reportHost: string;
  name: string;
  hostProperties: HostProperties;
};

type Policy = {
  policyName: string;
  preferences: Preferences;
  familySelection: FamilySelection;
  individualPluginSelection: IndividualPluginSelection;
};

type IndividualPluginSelection = {
  pluginItems: PluginItem[];
};

type PluginItem = {
  pluginId: string;
  pluginName: string;
  family: string;
  status: string;
};

type FamilySelection = {
  familyItems: FamilyItem[];
};

type FamilyItem = {
  familyName: string;
  status: string;
};
type Preferences = {
  serverPreferences: ServerPreferences;
  pluginPreferences: PluginPreferences;
};

type ServerPreferences = {
  preferences: Preference[];
};

type Preference = {
  name: string;
  value: string;
};

type PluginPreferences = {
  items: PluginPreferencesItem[];
};

type PluginPreferencesItem = {
  name: string;
  pluginId: string;
  fullName: string;
  preferenceName: string;
  preferenceType: string;
  preferenceValues: string;
  selectedValues: string;
};

type ReportItem = {
  port: string | null;
  svcName: string | null;
  protocol: string | null;
  severity: string | null;
  plugin: Plugin;
  description: string;
  fname: string;
  riskFactor: string;
  scriptVersion: string;
  solution: string | null;
  synopsis?: string;
  seeAlso?: string;
  cpe?: string;
  xref?: string;
  vulnPublicationDate?: string;
  cwe?: string;
  cve?: string;
  cvss3BaseScore?: string;
  cvss3Vector?: string;
  cvssBaseScore?: string;
  cvssScoreSource?: string;
  cvssVector?: string;
  iavt?: string;
  compliance?: string;
  cm?: CM;
};

type Plugin = {
  id: string | null;
  name: string | null;
  family: string | null;
  modificationDate: string;
  publicationDate: string;
  type: string;
  output?: string;
};

type CM = {
  checkName: string;
  source: string;
  auditFile: string;
  checkId: string;
  policyValue: string;
  functionalId: string;
  info: string;
  result: string;
  informationalId: string;
  reference: string;
  solution: string;
};

type HostProperties = {
  hostEndTimestamp: string;
  hostEnd: string;
  cpe4: string;
  cpe3: string;
  cpe2: string;
  cpe1: string;
  cpe0: string;
  patchSummaryTotalCves: string;
  cpe: string;
  os: string;
  operatingSystemConf: string;
  operatingSystemMethod: string;
  sshFingerprint: string;
  systemType: string;
  operatingSystem: string;
  sapNetweaverAsBanner: string;
  tracerouteHop1: string;
  tracerouteHop0: string;
  sinfpMlPrediction: string;
  sinfpSignature: string;
  hostFqdn: string;
  hostRdns: string;
  hostIp: string;
  hostStartTimestamp: string;
  hostStart: string;
};

function parseXmlAsync(xml: string): Promise<any> {
  return new Promise((resolve, reject) => {
    parseString(xml, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

function camelize(str: string) {
  return str
    .slice(1, str.length - 1)
    .toLowerCase()
    .replace(/[^a-zA-Z0-9]+(.)/g, (m, chr) => chr.toUpperCase());
}

async function createComplianceItemAsync(
  reportItem: any,
): Promise<ReportItem | null> {
  return {
    port: reportItem.getAttribute('port'),
    svcName: reportItem.getAttribute('svc_name'),
    protocol: reportItem.getAttribute('protocol'),
    severity: reportItem.getAttribute('severity'),
    plugin: {
      id: reportItem.getAttribute('pluginID'),
      name: reportItem.getAttribute('pluginName'),
      family: reportItem.getAttribute('pluginFamily'),
      modificationDate: reportItem.getElementsByTagName(
        'plugin_modification_date',
      )?.[0]?.innerHTML,
      publicationDate: reportItem.getElementsByTagName(
        'plugin_publication_date',
      )?.[0]?.innerHTML,
      type: reportItem.getElementsByTagName('plugin_type')?.[0]?.innerHTML,
    },
    description: reportItem.getElementsByTagName('description')?.[0]?.innerHTML,
    fname: reportItem.getElementsByTagName('fname')?.[0]?.innerHTML,
    riskFactor: reportItem.getElementsByTagName('risk_factor')?.[0]?.innerHTML,
    scriptVersion:
      reportItem.getElementsByTagName('script_version')?.[0]?.innerHTML,
    solution: reportItem.getElementsByTagName('solution')?.[0]
      ? reportItem.getElementsByTagName('solution')?.[0]?.innerHTML
      : null,
    compliance: reportItem.getElementsByTagName('compliance')?.[0]?.innerHTML,
    cm: {
      checkName: reportItem.getElementsByTagName(
        'cm:compliance-check-name',
      )?.[0]?.innerHTML,
      source: reportItem.getElementsByTagName('cm:compliance-source')?.[0]
        ?.innerHTML,
      auditFile: reportItem.getElementsByTagName(
        'cm:compliance-audit-file',
      )?.[0]?.innerHTML,
      checkId: reportItem.getElementsByTagName('cm:compliance-check-id')?.[0]
        ?.innerHTML,
      policyValue: reportItem.getElementsByTagName(
        'cm:compliance-policy-value',
      )?.[0]?.innerHTML,
      functionalId: reportItem.getElementsByTagName(
        'cm:compliance-functional-id',
      )?.[0]?.innerHTML,
      info: reportItem.getElementsByTagName('cm:compliance-info')?.[0]
        ?.innerHTML,
      result: reportItem.getElementsByTagName('cm:compliance-result')?.[0]
        ?.innerHTML,
      informationalId: reportItem.getElementsByTagName(
        'cm:compliance-informational-id',
      )?.[0]?.innerHTML,
      reference: reportItem.getElementsByTagName('cm:compliance-reference')?.[0]
        ?.innerHTML,
      solution: reportItem.getElementsByTagName('cm:compliance-solution')?.[0]
        ?.innerHTML,
    },
  };
}
async function createVulnerabilityItemAsync(
  reportItem: any,
): Promise<ReportItem | null> {
  return {
    port: reportItem.$.port,
    svcName: reportItem.$.svc_name,
    protocol: reportItem.$.protocol,
    severity: reportItem.$.severity,
    plugin: {
      id: reportItem.$.pluginID,
      name: reportItem.$.pluginName,
      family: reportItem.$.pluginFamily,
      modificationDate: reportItem.plugin_modification_date?.[0],
      publicationDate: reportItem.plugin_publication_date?.[0],
      type: reportItem.plugin_type?.[0],
      output: reportItem.plugin_output?.[0],
    },
    description: reportItem.description?.[0],
    fname: reportItem.fname?.[0],
    riskFactor: reportItem.risk_factor?.[0],
    scriptVersion: reportItem.script_version?.[0],
    solution: reportItem.solution?.[0] ? reportItem.solution?.[0] : null,
    synopsis: reportItem.synopsis?.[0],
    seeAlso: reportItem.see_also?.[0],
    cpe: reportItem.cpe?.[0],
    xref: reportItem.xref?.[0],
    vulnPublicationDate: reportItem.vuln_publication_date?.[0],
    cwe: reportItem.cwe?.[0],
    cve: reportItem.cve?.[0],
    iavt: reportItem.iavt?.[0],
    cvss3BaseScore: reportItem.cvss3_base_score?.[0],
    cvss3Vector: reportItem.cvss3_vector?.[0],
    cvssBaseScore: reportItem.cvss_base_score?.[0],
    cvssScoreSource: reportItem.cvss_score_source?.[0],
    cvssVector: reportItem.cvss_vector?.[0],
  };
}

/**
 *  Parses nessus xml output to a javascript object
 *
 * @param {string} xml
 *
 * @returns {Scan} The parsed output
 */

export async function NessusParser(
  xml: string,
  removePreferences: boolean = false,
): Promise<Scan | null> {
  try {
    const parsed = await parseXmlAsync(xml);
    if (!parsed) {
      return null;
    }
    const policy: Policy = {
      policyName: parsed.NessusClientData_v2.Policy[0].policyName[0],
      preferences: {
        serverPreferences: {
          preferences: [],
        },
        pluginPreferences: {
          items: [],
        },
      },
      familySelection: {
        familyItems: [],
      },
      individualPluginSelection: {
        pluginItems: [],
      },
    };
    if (removePreferences === false) {
      for (const serverPreference of parsed.NessusClientData_v2.Policy[0]
        .Preferences[0].ServerPreferences[0].preference || []) {
        policy.preferences.serverPreferences.preferences.push({
          name: serverPreference.name?.[0],
          value: serverPreference.value?.[0],
        });
      }

      for (const pluginPreference of parsed.NessusClientData_v2.Policy[0]
        .Preferences[0].PluginsPreferences[0].item || []) {
        policy.preferences.pluginPreferences.items.push({
          name: pluginPreference.pluginName?.[0],
          pluginId: pluginPreference.pluginId?.[0],
          fullName: pluginPreference.fullName?.[0],
          preferenceName: pluginPreference.preferenceName?.[0],
          preferenceType: pluginPreference.preferenceType?.[0],
          preferenceValues: pluginPreference.preferenceValues?.[0],
          selectedValues: pluginPreference.selectedValue?.[0],
        });
      }

      for (const familyItem of parsed.NessusClientData_v2.Policy[0]
        .FamilySelection[0].FamilyItem || []) {
        policy.familySelection.familyItems.push({
          familyName: familyItem.FamilyName?.[0],
          status: familyItem.Status?.[0],
        });
      }

      for (const pluginSelection of parsed.NessusClientData_v2.Policy[0]
        .IndividualPluginSelection[0].PluginItem || []) {
        policy.individualPluginSelection.pluginItems.push({
          pluginId: pluginSelection.PluginId?.[0],
          pluginName: pluginSelection.PluginName?.[0],
          family: pluginSelection.Family?.[0],
          status: pluginSelection.Status?.[0],
        });
      }
    }

    const reportName: string =
      parsed.NessusClientData_v2?.Report[0].$?.name || '';
    const reportHosts: any[] =
      parsed.NessusClientData_v2?.Report[0].ReportHost || [];
    const reports: Report[] = [];

    for (const reportHost of reportHosts) {
      const report: Report = {
        name: reportName,
        reportHost: JSON.stringify(reportHost?.$?.name || ''),
        reportItems: [],
        hostProperties: {
          hostEndTimestamp: '',
          hostEnd: '',
          cpe4: '',
          cpe3: '',
          cpe2: '',
          cpe1: '',
          cpe0: '',
          patchSummaryTotalCves: '',
          cpe: '',
          os: '',
          operatingSystemConf: '',
          operatingSystemMethod: '',
          sshFingerprint: '',
          systemType: '',
          operatingSystem: '',
          sapNetweaverAsBanner: '',
          tracerouteHop1: '',
          tracerouteHop0: '',
          sinfpMlPrediction: '',
          sinfpSignature: '',
          hostFqdn: '',
          hostRdns: '',
          hostIp: '',
          hostStartTimestamp: '',
          hostStart: '',
        },
      };
      for (const reportItem of reportHost.ReportItem || []) {
        const vulnerabilityItem: ReportItem | null =
          await createVulnerabilityItemAsync(reportItem);
        if (vulnerabilityItem) {
          report.reportItems.push(vulnerabilityItem);
        }
      }

      const hostPropertiesArray = Array.from(
        reportHost?.HostProperties?.[0] || [],
      ) as any[];

      if (hostPropertiesArray?.length) {
        const hostProperties: Partial<HostProperties> = {};
        for (const child of hostPropertiesArray) {
          const index: string = camelize(JSON.stringify(child?.$?.name));

          hostProperties[index as keyof HostProperties] = child?.$?.value;
        }
        report.hostProperties = hostProperties as HostProperties;
      }
      reports.push(report);
    }

    const scan: Scan = {
      policy,
      reports,
    };

    return scan;
  } catch (error) {
    console.error('Error parsing Nessus XML:', error);
    return null;
  }
}
