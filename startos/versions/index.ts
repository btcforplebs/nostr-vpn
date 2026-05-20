import { VersionGraph } from '@start9labs/start-sdk'
import { currentVersion } from './current'

export const versionGraph = VersionGraph.of({
  current: currentVersion,
  other: [],
})
