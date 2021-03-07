extern crate debugger;
extern crate log;
extern crate env_logger;
extern crate basic_mutator;


pub mod mesofile;

use std::fs;
use std::path::{Path, PathBuf};
use debugger::{Debugger, ExitType};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use log::info;
use std::cell::Cell;
use basic_mutator::{Mutator, InputDatabase};

use std::time::Instant;

/// Routine to invoke on module loads
fn modload_handler(dbg: &mut Debugger, modname: &str, _base: usize) {
    // Calculate what the filename for a cached meso would be for this module
    let path = format!("cache\\{}.meso", modname);  // mesofile::compute_cached_meso_name(dbg, modname, base);
    //print!("loading {} \n", path);
    // Attempt to load breakpoints from the meso file
    mesofile::load_meso(dbg, &Path::new(&path));
}


pub struct Rng {
    /// Interal xorshift seed
    seed: Cell<u64>,
    
}

impl Rng {
    /// Create a new, TSC-seeded random number generator
    pub fn new() -> Self {
        let ret = Rng {
            seed: Cell::new(unsafe { core::arch::x86::_rdtsc() }),
        };

        for _ in 0..1000 {
            let _ = ret.rand();
        }

        ret
    }

    /// Created a RNG with a fixed `seed` value
    pub fn seeded(seed: u64) -> Self {
        Rng {
            seed: Cell::new(seed),
        }
    }

    /// Get a random 64-bit number using xorshift
    pub fn rand(&self) -> usize {
        let mut seed = self.seed.get();
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        self.seed.set(seed);
        seed as usize
    }
}
struct Stats{

    
    pub rng: Rng, 

    // HashSet

    input_hash_db: HashSet<Arc<Vec<u8>>>,

    // Current number of testcases
    fuzz_cases: u64,

    // Fuzzer's start time.
    start_time:Instant,
    
    // key -> module + offset
    // param -> bp frequency
    pub coverage: HashMap<(Arc<String>, usize), Arc<Vec<u8>>>,

    // All inputs which achieved coverage
    pub uniq_inputs: Vec<Arc<Vec<u8>>>,

    // crashes, tuple is filename, input in bytes
    crashes: Vec<(String, Arc<Vec<u8>>)>,

    crash_hashdb: HashSet<String>,
}

impl Stats{
    pub fn new() -> Self{
        info!("initializing with default settings.");
        Stats{
            crash_hashdb: HashSet::new(),
            rng: Rng::new(),
            input_hash_db: HashSet::new(),
            fuzz_cases: 0,
            start_time: Instant::now(),
            coverage: HashMap::new(),
            uniq_inputs: Vec::new(),
            crashes: Vec::new(),
        }
    }


    pub fn new_corpus(directory: &str) -> Self{
        info!("initializing with directory \"{}\" ", directory);
        let filenames = traverse(Path::new(directory));

        let mut corpus:Vec<Arc<Vec<u8>>> = Vec::new();
        let mut hashdb:HashSet<Arc<Vec<u8>>> =  HashSet::new();

        for fname in filenames.iter(){
            
            let data = Arc::new(std::fs::read(fname).expect("could not read a file from corpus."));
            if hashdb.insert(data.clone()){
                corpus.push(data.clone());
            }

        }

        info!("len of corpus: {} len of hashdb: {}\n", hashdb.len(), corpus.len());
        Stats{
            crash_hashdb: HashSet::new(),
            rng: Rng::new(),
            input_hash_db: hashdb,
            fuzz_cases: 0,
            start_time: Instant::now(),
            coverage: HashMap::new(),
            uniq_inputs: corpus,
            crashes: Vec::new(),
        }
    }
    pub fn crash(&mut self, filename: &str, crash: Arc<Vec<u8>>){
        print!("CRASSHSHSHSH\n");
        if self.crash_hashdb.insert(filename.to_owned()){
            self.crashes.push((filename.to_string(), crash.clone()));
            std::fs::write(filename ,&*crash).expect("could not write crash");
            info!("new crash: {} ", filename);
        }

    }
    pub fn rand_input(&self) -> Arc<Vec<u8>>{
        //print!("inputs: {:?}\n", self.uniq_inputs);
        let rngchoice = self.rng.rand();
        let len = self.uniq_inputs.len();
        self.uniq_inputs[rngchoice % len].clone()
    }
    pub fn increment_cases(&mut self){
        self.fuzz_cases+=1;
    }
    pub fn print_stats(&self){
        let uptime = (Instant::now() - self.start_time).as_secs();
        let cases = self.fuzz_cases;
        info!("fcps: {}, coverage: {} cases: {} crashes: {}, uniq_inputs: {}", cases/uptime, 
                        self.coverage.len(), cases, self.crashes.len(), self.uniq_inputs.len());
    }
    pub fn mutate(&mut self, mutator : &mut Mutator) -> Arc<Vec<u8>>{
        let inp = self.rand_input();
        if inp.len() < 1 {
            info!("empty input?\n");
            mutator.input.clear();
            mutator.input.resize(16, 0);
        }
        else{
            mutator.input.clear();
            mutator.input.extend_from_slice(&inp);
            
        }
        mutator.mutate(self.rng.rand() % 25, self);
        Arc::new(mutator.input.clone())
    }
}
impl InputDatabase for Stats {
    fn num_inputs(&self) -> usize { self.uniq_inputs.len() }
    fn input(&self, idx: usize) -> Option<&[u8]> {
        Some(&self.uniq_inputs[idx])
    }
}

fn get_input(threadid: i32, stats: Arc<Mutex<Stats>>, mutator: &mut Mutator) -> (String, Arc<Vec<u8>>){


    let mut stats = stats.lock().unwrap();
    let input = stats.mutate(mutator);

    let fname = format!("R:\\cur_input_{}.jp2", threadid);
    std::fs::write(fname.clone(), &*input).expect("couldn't write target file");

    return (fname, input)
}

fn main() {
    std::env::set_var("RUST_LOG","info");
    // Setup logging
    env_logger::init();
    // mesos.exe -p pid mesos_file0 mesos_file1 mesos_file2 
    // or mesos.exe mesos_file0 mesos_file1 mesos_file2 -- ./exe arg0 arg1 arg2

    // Usage and argument parsing
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print!("Usage: mesos.exe -p <pid> <options> <mesos files>\n");
        print!("    or mesos.exe <options> <mesos files> -- program.exe <arguments>\n");
        print!("    --freq               - \
               Treats all breakpoints as frequency breakpoints\n");
        print!("    --dir        - \
               directory with all testcases\n");
        print!("    --verbose            - \
               Enables verbose prints for debugging\n");
        print!("    --follow-fork        - \
               Capture coverage for child processes\n");
        print!("    directory with testcases");

        return;
    }


    let mut pid: Option<u32> = None;
    let mut follow_fork_enabled = true;
    let mut directory: &str = "";
    let mut argv: Vec<String> = Vec::new();
    let mut argv_set: bool = false;

    // todo: load corpus
    if args.len() > 2 {
        for (ii, arg) in args[1..].iter().enumerate() {
            if arg == "-p" {
                pid = Some(args.get(ii + 2)
                .expect("No PID specified with -p argument").parse().unwrap());
            }
            else if arg == "--follow-fork" {
                follow_fork_enabled = true;
            }
            else if arg == "--" {
                argv.extend_from_slice(&args[ii + 2..]);
                argv_set = true;
                break;
            }
            else { // Has to be a mesofile
                //mesofile::load_meso(&mut dbg, Path::new(arg));
                directory = arg;
            }
        }
    }
    let stats: Arc<Mutex<Stats>> = {
        if directory == ""{
            Arc::new(Mutex::new(Stats::new()))
        }
        else{
            Arc::new(Mutex::new(Stats::new_corpus(directory)))
        }
    };
    if !(argv_set ==true && argv.len() >0){
        print!( "Argv not provided\n");
        return;
    };

    let mut cache: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    for meso in traverse_extension(Path::new("cache"), "meso"){
        cache.insert(meso.to_owned(), fs::read(meso).unwrap());
    }


    //TODO: ADD FREQUENCY STATE COVERAGE
    let idx = argv.iter().position(|bruh| bruh == "replaceme").expect("could not find \"replaceme\" arg");
    let idx_two = argv.iter().position(|bruh| bruh == "replaceme2").expect("could not find \"replaceme2\" arg");
    for threadid in 0..24{
        {
            let cache_thread = cache.clone();
            let mut args = argv.clone();
            let stats = stats.clone();
            
           
            std::thread::spawn(move || {
                let rng = Rng::new();
                let max_size = 1024*1024*5;
                let mut mutator = Mutator::new().seed(rng.rand() as u64).max_input_size(max_size).printable(false);
                let tid = format!("p{}",threadid);
                loop {
                    let (fname, inp) = get_input(threadid, stats.clone(), &mut mutator); // get_input -> returns file name path

                    args[idx] = fname.clone();
                    args[idx_two] = tid.clone();
                    //print!("executing {:?}\n", args);
                    let mut dbg:Debugger;
                    
                    
                    if pid.is_none() && args.len() > 0 {
                        dbg = Debugger::spawn_proc(&args, follow_fork_enabled);
                    }
                    else {
                        dbg = Debugger::attach(pid.unwrap() as u32);
                    }
                    dbg.register_modload_callback(Box::new(modload_handler),cache_thread.clone());
    
                    // Debug forever
                    let exit: ExitType = dbg.run();
                    let mut stats = stats.lock().unwrap();
                    match exit{
                        ExitType::Crash(fname) => {
                            stats.crash(&fname, inp);
                        }
                        ExitType::ExitCode(_code) => {
                            let mut coverage = HashMap::new();
                            std::mem::swap(&mut dbg.coverage, &mut coverage);
                            std::mem::drop(dbg);
                            for (_, (module, offset, _, _)) in coverage.iter() {
                                let key = (module.clone(), *offset);
                                
                                
                                if !stats.coverage.contains_key(&key){
                                    if stats.input_hash_db.insert(inp.clone()){
                                        stats.uniq_inputs.push(inp.clone());
                                    }
                                    
                                    stats.coverage.insert(key.clone(),   inp.clone());
                                }
                                // if the fuzzer is faster, you could track state n shit but nah


                                // //FIX THIS
                                // else{
                                //     // this only tracks if the state is HIGHER, maybe we need it to be less or whatever idk
                                //     if freq{
                                //         let mut fq = stats.coverage.get_mut(key).unwrap();
                                //         if fq < freq{
                                            
                                //         }
                                //     }
                                // }
                                
                            }
                            
                        } 
                    }
                    stats.increment_cases();
                    std::fs::remove_file(&fname).expect("could not remove file.");
                }
                

            });
        }
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let shit = stats.lock().unwrap();
        shit.print_stats();
    }
    
}

fn traverse(dir: &Path) -> Vec<PathBuf>{
    let mut ret: Vec<PathBuf> = Vec::new();
    
    for entry in fs::read_dir(dir).expect("COULD NOT READ THIS DIR") {
        let entry = entry.expect("Path Entry is invalid.").path();

        if entry.is_dir(){
            ret.append(&mut traverse(&entry));   
        }
        else{
            ret.push(entry);
        }
    }
    ret
}

fn traverse_extension(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut ret: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir).expect("COULD NOT READ THIS DIR") {
        let entry = entry.expect("Path Entry is invalid.").path();

        if entry.is_dir(){
            ret.append(&mut traverse_extension(&entry, extension));   
        }
        else{
            if entry.extension() == None{
                continue;
            }
            if entry.extension().unwrap() == extension{
                ret.push(entry);
            }
            
        }
    }
    ret
}