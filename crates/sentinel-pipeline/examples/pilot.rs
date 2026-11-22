use std::{env, fs};

use sentinel_pipeline::workflow::{
    self, DockerHosts, Images, Options, Phase, WorkflowFile, analyze, plan,
};

const IMAGE: &str = "docker.io/library/ubuntu:24.04@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662";

fn main() {
    let mut args = env::args().skip(1);
    let revision = args.next().unwrap();
    let dir = args.next().unwrap();
    let mut files: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .map(|p| {
            (
                format!(
                    "{}/{}",
                    workflow::WORKFLOW_DIRECTORY,
                    p.file_name().unwrap().to_string_lossy()
                ),
                fs::read_to_string(&p).unwrap().replace("\r\n", "\n"),
            )
        })
        .collect();
    files.sort();
    for (path, text) in &files {
        let one = [WorkflowFile { path, text }];
        println!("== {path}");
        let inventory = match analyze(&revision, &one, DockerHosts::MicrovmGuests) {
            Ok(i) => i,
            Err(e) => {
                println!("  ANALYZE REFUSED: {e}");
                continue;
            }
        };
        for w in &inventory.workflows {
            println!("  jobs: {}", w.jobs.len());
        }
        for phase in [Phase::Label, Phase::Shadow, Phase::Switch, Phase::Disable] {
            let options = Options {
                docker: DockerHosts::MicrovmGuests,
                native: true,
                images: Images {
                    linux: Some(IMAGE),
                    linux_arm64: Some(IMAGE),
                    windows: Some(IMAGE),
                },
                phase,
            };
            match plan(&inventory, &one, &options) {
                Err(e) => println!("  {phase:?} PLAN REFUSED: {e}"),
                Ok(p) => {
                    for w in &p.workflows {
                        println!(
                            "  {phase:?}: changes={} shadow={} dropped={} disabled={} kept={}",
                            w.changes.len(),
                            w.shadow.len(),
                            w.dropped.len(),
                            w.disabled.len(),
                            w.kept.len()
                        );
                        if phase == Phase::Shadow && env::var_os("DIFF").is_some() {
                            println!("{}", w.diff);
                        }
                        if phase == Phase::Label {
                            for c in &w.changes {
                                println!(
                                    "    move {} : {:?} -> {:?}",
                                    c.job,
                                    c.before.trim(),
                                    c.after.trim()
                                );
                            }
                            for k in &w.kept {
                                println!("    kept {} {:?} varies={}", k.job, k.reasons, k.varies);
                            }
                            match (&w.native, w.native_refused) {
                                (Some(n), _) => {
                                    println!("    native: {} notes={:?}", n.path, n.notes);
                                    for j in &n.jobs {
                                        println!(
                                            "      {} -> {:?} kept={:?}",
                                            j.github, j.jobs, j.kept
                                        );
                                    }
                                }
                                (None, r) => println!("    native refused: {r:?}"),
                            }
                        }
                    }
                }
            }
        }
    }
}
