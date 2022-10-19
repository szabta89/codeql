/**
 * Adapted from the SQL injection query.
 */

import ruby
import codeql.ruby.Concepts
import codeql.ruby.DataFlow
import codeql.ruby.dataflow.BarrierGuards
import codeql.ruby.dataflow.RemoteFlowSources
import codeql.ruby.TaintTracking
import DataFlow::PathGraph

class BenchmarkConfiguration extends TaintTracking::Configuration {
  BenchmarkConfiguration() { this = "BenchmarkConfiguration" }

  override predicate isSource(DataFlow::Node source) { exists(source.asParameter()) }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode cn | sink = cn.getArgument(_))
  }

  override predicate isSanitizer(DataFlow::Node node) {
    node instanceof StringConstCompareBarrier or
    node instanceof StringConstArrayInclusionCallBarrier
  }
}

from BenchmarkConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
